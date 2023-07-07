from sqlalchemy.orm import Session

from . import models, schemas

from passlib.context import CryptContext


pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db: Session, username: str):
    return db \
        .query(models.User) \
        .filter(models.User.username == username) \
        .first()


def get_user_by_email(db: Session, email: str):
    return db \
        .query(models.User) \
        .filter(models.User.email == email) \
        .first()


def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = get_password_hash(user.password)

    db_user = models.User(
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        salary=user.salary,
        promotion_date=user.promotion_date,
        hashed_password=hashed_password
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user
