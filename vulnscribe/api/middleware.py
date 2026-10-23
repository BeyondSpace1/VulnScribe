
from starlette.responses import JSONResponse


class RequestBodyLimitMiddleware:
    """Reject HTTP request bodies exceeding a configured byte limit."""

    def __init__(self, app, max_body_size: int = 1_048_576):
        if max_body_size <= 0:
            raise ValueError("max_body_size must be positive")

        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_lengths = [
            value
            for key, value in scope.get("headers", [])
            if key.lower() == b"content-length"
        ]

        if len(content_lengths) > 1:
            await self._reject(scope, receive, send, 400,
                               "Invalid Content-Length header")
            return

        if content_lengths:
            try:
                declared_size = int(content_lengths[0])
            except ValueError:
                await self._reject(scope, receive, send, 400,
                                   "Invalid Content-Length header")
                return

            if declared_size < 0:
                await self._reject(scope, receive, send, 400,
                                   "Invalid Content-Length header")
                return

            if declared_size > self.max_body_size:
                await self._reject(scope, receive, send, 413,
                                   "Request body too large")
                return

        body = bytearray()

        while True:
            message = await receive()

            if message["type"] == "http.disconnect":
                return

            if message["type"] != "http.request":
                continue

            chunk = message.get("body", b"")

            if len(body) + len(chunk) > self.max_body_size:
                await self._reject(scope, receive, send, 413,
                                   "Request body too large")
                return

            body.extend(chunk)

            if not message.get("more_body", False):
                break

        body_bytes = bytes(body)
        replayed = False

        async def replay_receive():
            nonlocal replayed

            if not replayed:
                replayed = True
                return {
                    "type": "http.request",
                    "body": body_bytes,
                    "more_body": False,
                }

            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(scope, receive, send, status_code, detail):
        response = JSONResponse(
            status_code=status_code,
            content={"detail": detail},
        )
        await response(scope, receive, send)
