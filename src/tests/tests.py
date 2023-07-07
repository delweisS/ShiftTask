import pytest

from fastapi import status
from fastapi.testclient import TestClient

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.main import app, get_db
from src.database import Base


SQLALCHEMY_DATABASE_URL = 'sqlite:///.//test_db.db'

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={'check_same_thread': False}
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(scope='module')
def access_token():
    return get_access_token()


def get_access_token():
    token_headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    token_response = client.post(
        '/token/',
        data={
            "grant_type": "password",
            "username": "testuser",
            "password": "test"
        },
        headers=token_headers
    )
    assert token_response.status_code == status.HTTP_200_OK

    token_data = token_response.json()
    assert 'access_token' in token_data

    return token_data['access_token']


@pytest.mark.user_creation
def test_create_success():
    response = client.post(
        '/users/',
        json={
            "email": "testemail@example.com",
            "username": "testuser",
            "full_name": "Test User",
            "salary": 200,
            "promotion_date": "2023-06-05",
            "password": "test",
        }
    )
    assert response.status_code == status.HTTP_200_OK

    user_data = response.json()
    assert user_data == {
        'id': 1,
        'username': 'testuser',
        'email': 'testemail@example.com',
        'full_name': 'Test User',
        'salary': 200.0,
        'promotion_date': '2023-06-05',
        'is_active': True
    }


@pytest.mark.user_creation
def test_create_fail_email_registered():
    response = client.post(
        '/users/',
        json={
            "email": "testemail@example.com",
            "username": "testuser2",
            "full_name": "Test User",
            "salary": 200,
            "promotion_date": "2023-06-05",
            "password": "test"
        }
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    data = response.json()
    assert data['detail'] == 'Email already registered'


@pytest.mark.user_creation
def test_create_fail_username_registered():
    response = client.post(
        '/users/',
        json={
            "email": "testemail2@example.com",
            "username": "testuser",
            "full_name": "Test User",
            "salary": 200,
            "promotion_date":
            "2023-06-05",
            "password": "test"
        }
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    data = response.json()
    assert data['detail'] == 'Username already registered'


@pytest.mark.user_creation
def test_create_fail_wrong_credentials():
    response = client.post(
        '/users/',
        json={
            "email": "testemail@example.com",
            "full_name": "Test User",
            "salary": 200,
            "promotion_date": "2023-06-05",
            "password": "test"
        }
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    data = response.json()
    assert data['detail'][0]['loc'][1] == 'username'
    assert data['detail'][0]['msg'] == 'field required'
    assert data['detail'][0]['type'] == 'value_error.missing'


def test_get_user_success(access_token):
    response = client.get(
        '/users/testuser/',
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == status.HTTP_200_OK

    user_data = response.json()
    assert user_data == {
        'full_name': 'Test User',
        'salary': 200.0,
        'promotion_date': '2023-06-05'
    }


def test_get_user_fail_not_authenticated():
    response = client.get(
        '/users/testuser/'
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    data = response.json()
    assert data['detail'] == 'Not authenticated'


def test_get_user_fail_wrong_user(access_token):
    response = client.get(
        '/users/wrong_user/',
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    data = response.json()
    assert data['detail'] == 'Not authenticated'
