from sqlalchemy import Boolean, Column, Integer, String, Float, Date

from .database import Base


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    salary = Column(Float)
    promotion_date = Column(Date)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
