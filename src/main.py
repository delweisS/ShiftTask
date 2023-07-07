from typing import Annotated
from functools import lru_cache
from datetime import datetime, timedelta

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from sqlalchemy.orm import Session

from .config import Settings
from . import crud, models, schemas
from .database import SessionLocal, engine


models.Base.metadata.create_all(bind=engine)

pwd_context: CryptContext = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
app = FastAPI()


@lru_cache()
def get_settings():
    return Settings()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(
        plain_password,
        hashed_password
):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(
        db: Session = Depends(get_db),
        username: str = None,
        password: str = None
):
    db_user = crud.get_user(db, username)

    if not db_user:
        return False
    if not verify_password(password, db_user.hashed_password):
        return False

    return db_user


def create_access_token(
        data: dict,
        settings: Annotated[Settings, Depends(get_settings)],
        expires_delta: timedelta | None = None
):
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )

    return encoded_jwt


def get_current_user(
        token: Annotated[str, Depends(oauth2_scheme)],
        settings: Annotated[Settings, Depends(get_settings)],
        db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        username: str = payload.get('sub')

        if username is None:
            raise credentials_exception

        token_data = schemas.TokenData(username=username)

    except JWTError:
        raise credentials_exception

    db_user = crud.get_user(db, username=token_data.username)

    if db_user is None:
        raise credentials_exception

    return db_user


def get_current_active_user(
        current_user: Annotated[schemas.User, Depends(get_current_user)]
):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    return current_user


@app.post("/token/", response_model=schemas.Token)
def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Annotated[Settings, Depends(get_settings)],
    db: Session = Depends(get_db),
):
    db_user = authenticate_user(db, form_data.username, form_data.password)

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    access_token = create_access_token(
        data={"sub": db_user.username},
        expires_delta=access_token_expires,
        settings=settings
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/users/", response_model=schemas.User)
def create_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db)
):
    if crud.get_user_by_email(db, email=user.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    if crud.get_user(db, username=user.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    return crud.create_user(db=db, user=user)


@app.get("/users/{username}/", response_model=schemas.UserDisplay)
def get_user_by_username(
    username: str,
    current_user: Annotated[schemas.User, Depends(get_current_active_user)],
):
    if username != current_user.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    return current_user
