import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict

from dacite import from_dict, Config


class ACMEBaseClass(ABC):
    @staticmethod
    @abstractmethod
    def from_json(data: str) -> "ACMEBaseClass":
        pass


class ChallengeTypes(Enum):
    DNS01 = "dns-01"
    HTTP01 = "http-01"
    TLSALPN01 = "tls-alpn-01"


class ChallengeStatus(Enum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"


@dataclass
class ACMEChallenge(ACMEBaseClass):
    type: ChallengeTypes = field()
    url: str = field()
    token: str = field()
    status: ChallengeStatus = field()

    @staticmethod
    def from_json(data: str) -> "ACMEBaseClass":
        return from_dict(
            data_class=ACMEChallenge,
            data=json.loads(data),
            config=Config(cast=[ChallengeStatus, ChallengeTypes],),
        )


@dataclass()
class ACMEOrder(ACMEBaseClass):
    status: ChallengeStatus = field()
    expires: str = field()
    identifiers: List[Dict] = field()
    finalize: str = field()
    authorizations: List[str] = field()
    wildcard: bool = field(default=False)
    notBefore: str = field(default=None)
    notAfter: str = field(default=None)

    @staticmethod
    def from_json(data: str) -> "ACMEBaseClass":
        return from_dict(
            data_class=ACMEOrder,
            data=json.loads(data),
            config=Config(
                cast=[ChallengeStatus, ChallengeTypes],
                forward_references={
                    "status": ChallengeStatus,
                    "challenges": List[ACMEChallenge],
                    "type": ChallengeTypes,
                },
            ),
        )


@dataclass
class ACMEAuthorization(ACMEBaseClass):
    status: ChallengeStatus = field()
    identifier: dict = field()
    challenges: List[ACMEChallenge] = field()
    expires: str = field()

    @staticmethod
    def from_json(data: str) -> "ACMEBaseClass":
        return from_dict(
            data_class=ACMEAuthorization,
            data=json.loads(data),
            config=Config(
                cast=[ChallengeStatus, ChallengeTypes],
                forward_references={
                    "status": ChallengeStatus,
                    "challenges": List[ACMEChallenge],
                    "type": ChallengeTypes,
                },
            ),
        )
