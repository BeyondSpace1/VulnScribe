from abc import ABC, abstractmethod

from vulnscribe.models import Finding, ScanTarget


class BaseScanner(ABC):
    scanner_name = "base"

    @abstractmethod
    def supports(self, target: ScanTarget) -> bool:
        raise NotImplementedError

    @abstractmethod
    def scan(self, target: ScanTarget) -> list[Finding]:
        raise NotImplementedError
