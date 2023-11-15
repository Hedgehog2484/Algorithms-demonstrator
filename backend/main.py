import uvicorn

from fastapi import FastAPI

from handlers import setup_handlers


def setup(app: FastAPI) -> None:
    """ Запуск и подгрузка различных компонентов приложения. """
    setup_handlers(app)


def main():
    app = FastAPI()
    setup(app)
    uvicorn.run(app, host="localhost", port=80)
