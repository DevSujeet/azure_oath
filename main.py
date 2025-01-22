# 

from contextlib import asynccontextmanager
from fastapi import FastAPI
import uvicorn
from routes import auth, protected

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("in life span")
    yield

def create_app(lifespan:lifespan) -> FastAPI:
    fastapi_app = FastAPI(title="sample Auth Service",
                          description="Oauth using Azure Entra ID",
                          version="0.0.1",
                          lifespan=lifespan
                          )
    # # Middleware Settings
    # fastapi_app.middleware("http")(add_process_time)

    # fastapi_app.add_middleware(RedisCacheMiddleware, cache_settings=cache_settings)

    # fastapi_app.add_exception_handler(SourceException, source_exception_handler)
    for router in get_fastapi_routers():
        fastapi_app.include_router(router)

    return fastapi_app


def get_fastapi_routers():
    return [
        protected.router,
        auth.router,
    ]

app = create_app(lifespan=lifespan)
# add_pagination(app)
if __name__ == "__main__":
    uvicorn.run("main:app")
