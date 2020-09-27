import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict

from dacite import from_dict, Config


class ACMEBaseClass(ABC):
    @staticmethod
    @abstractmethod
    def from_json(data: Dict) -> "ACMEBaseClass":
        pass


class ChallengeType(Enum):
    DNS01 = "dns-01"
    HTTP01 = "http-01"
    TLSALPN01 = "tls-alpn-01"


class ChallengeStatus(Enum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"


class OrderStatus(Enum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    READY = "ready"
    PROCESSING = "processing"


@dataclass
class ACMEChallenge(ACMEBaseClass):
    type: ChallengeType = field()
    url: str = field()
    token: str = field()
    status: ChallengeStatus = field()

    @staticmethod
    def from_json(data: Dict) -> "ACMEChallenge":
        return from_dict(
            data_class=ACMEChallenge,
            data=data,
            config=Config(cast=[ChallengeStatus, ChallengeType],),
        )


@dataclass()
class ACMEOrder(ACMEBaseClass):
    url_id: str = field()
    status: OrderStatus = field()
    expires: str = field()
    identifiers: List[Dict] = field()
    finalize: str = field()
    authorizations: List[str] = field()
    wildcard: bool = field(default=False)
    notBefore: str = field(default=None)
    notAfter: str = field(default=None)

    @staticmethod
    def from_json(data: Dict) -> "ACMEOrder":
        return from_dict(
            data_class=ACMEOrder,
            data=data,
            config=Config(
                cast=[OrderStatus, ChallengeType],
                forward_references={
                    "status": OrderStatus,
                    "challenges": List[ACMEChallenge],
                    "type": ChallengeType,
                },
            ),
        )


@dataclass
class ACMEAuthorization(ACMEBaseClass):
    url_id: str = field()
    status: ChallengeStatus = field()
    identifier: dict = field()
    challenges: List[ACMEChallenge] = field()
    expires: str = field()

    @staticmethod
    def from_json(data: Dict) -> "ACMEAuthorization":
        return from_dict(
            data_class=ACMEAuthorization,
            data=data,
            config=Config(
                cast=[ChallengeStatus, ChallengeType],
                forward_references={
                    "status": ChallengeStatus,
                    "challenges": List[ACMEChallenge],
                    "type": ChallengeType,
                },
            ),
        )


@dataclass
class ACMEAccount(ACMEBaseClass):
    url_id: str = field()
    status: ChallengeStatus = field()
    contact: List[str] = field()
    orders: str = field()

    @staticmethod
    def from_json(data: Dict) -> "ACMEAccount":
        return from_dict(
            data_class=ACMEAccount,
            data=data,
            config=Config(
                cast=[ChallengeStatus], forward_references={"status": ChallengeStatus,},
            ),
        )
