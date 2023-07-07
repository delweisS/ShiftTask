from datetime import date

from pydantic import BaseModel


class UserCreate(BaseModel):
    email: str
    username: str
    full_name: str
    salary: float
    promotion_date: date
    password: str


class User(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    salary: float
    promotion_date: date
    is_active: bool

    class Config:
        orm_mode = True


class UserDisplay(BaseModel):
    full_name: str
    salary: float
    promotion_date: date

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None
