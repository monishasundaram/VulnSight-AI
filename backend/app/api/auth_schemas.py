from pydantic import BaseModel, EmailStr, Field


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class PublicUser(BaseModel):
    id: str
    email: str
    role: str


class AuthResponse(BaseModel):
    user: PublicUser
    csrfToken: str


class SessionResponse(AuthResponse):
    pass
