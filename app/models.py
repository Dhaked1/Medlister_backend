from pydantic import BaseModel, Field, computed_field
from typing import Annotated, Literal, Optional

class Patient(BaseModel):
    id: Annotated[str, Field(..., description="The ID of the patient", examples=["P001"])]
    name: Annotated[str, Field(..., description="The name of the patient", examples=["John Doe"])]
    age: Annotated[int, Field(..., description="The age of the patient", examples=[30], ge=0, le=120)]
    gender: Annotated[Literal['Male','Female','Other'], Field(..., description="The gender of the patient", examples=["Male"])]
    city: Annotated[str, Field(..., description="The city of the patient", examples=["New York"])]
    height: Annotated[float, Field(..., description="The height of the patient", examples=[1.75], ge=0)]
    weight: Annotated[float, Field(..., description="The weight of the patient", examples=[70.5], ge=0)]

    @computed_field
    @property
    def bmi(self) -> float:
        return round(self.weight / (self.height ** 2), 2)

    @computed_field
    @property
    def bmi_category(self) -> str:
        if self.bmi < 18.5:
            return 'Underweight'
        elif self.bmi < 25:
            return 'Normal'
        elif self.bmi < 30:
            return 'Overweight'
        else:
            return 'Obese'

class PatientUpdate(BaseModel):
    name: Optional[str] = None
    city: Optional[str] = None
    age: Optional[int] = None
    gender: Optional[Literal["Male", "Female", "Other"]] = None
    height: Optional[float] = None
    weight: Optional[float] = None

class SignupRequest(BaseModel):
    name: Annotated[str, Field(..., description="User's full name", examples=["John Doe"])]
    email: Annotated[str, Field(..., description="User's email address", examples=["john@example.com"])]
    password: Annotated[str, Field(..., description="User's password (will be hashed)", examples=["SecurePass123!"], min_length=6)]

class LoginRequest(BaseModel):
    email: Annotated[str, Field(..., description="User's email address", examples=["john@example.com"])]
    password: Annotated[str, Field(..., description="User's password", examples=["SecurePass123!"])]