import pytest
from aiohttp import web
from app import app

@pytest.fixture
def test_client(loop, aiohttp_client):
    return loop.run_until_complete(aiohttp_client(app))

async def test_register(test_client):
    resp = await test_client.post("/register", json={"username": "test", "password": "test123"})
    assert resp.status == 200

async def test_login(test_client):
    await test_client.post("/register", json={"username": "test", "password": "test123"})
    resp = await test_client.post("/login", json={"username": "test", "password": "test123"})
    assert resp.status == 200
    data = await resp.json()
    assert "token" in data

async def test_shorten_protected(test_client):
    resp = await test_client.post("/", data="https://example.com ")
    assert resp.status == 401  # Доступ запрещён без токена

