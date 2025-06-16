from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import string
import secrets
from textwrap import wrap
from typing import Optional

app = FastAPI(title="Password Generator", description="Server-side rendered password generator")

# Setup Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Optional: serve static files (CSS, JS, etc.)
# app.mount("/static", StaticFiles(directory="static"), name="static")


def charset(length: int = 6) -> str:
    """Generate a random string of lowercase letters"""
    return ''.join([secrets.choice(string.ascii_lowercase) for _ in range(length)])


def superset(
    length: int = 3,
    set_length: int = 6,
    numbers: int = 1,
    uppercase: int = 1,
    separator: str = '-'
) -> str:
    """Generate a formatted password with specified parameters"""
    max_chars = set_length * length
    
    if numbers + uppercase > max_chars:
        raise ValueError(
            f'The amount of numbers ({numbers}) plus uppercase letters ({uppercase}) '
            f'must be less than or equal to the total characters ({max_chars})'
        )

    sets = []
    for _ in range(length):
        sets.append(charset(set_length))

    all_chars = ''.join(sets)

    # Convert to list for easier manipulation
    all_chars = list(all_chars)

    # Insert uppercase letters
    for _ in range(uppercase):
        available_indices = [
            i for i, char in enumerate(all_chars) 
            if char.isalpha() and char.islower()
        ]
        
        if not available_indices:
            break
            
        index = secrets.choice(available_indices)
        all_chars[index] = all_chars[index].upper()

    # Insert numbers
    for _ in range(numbers):
        available_indices = [
            i for i, char in enumerate(all_chars) 
            if char.isalpha() and char.islower()
        ]
        
        if not available_indices:
            break
            
        index = secrets.choice(available_indices)
        all_chars[index] = secrets.choice(string.digits)

    # Convert back to string
    all_chars = ''.join(all_chars)

    # Split and join with separators
    sets = wrap(all_chars, set_length)
    result = separator.join(sets)

    return result


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Display the password generator form with a pre-generated password"""
    # Generate a password with default settings on page load
    default_password = superset(
        length=3,
        set_length=6,
        numbers=1,
        uppercase=1,
        separator="-"
    )
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "generated_password": default_password,
        "form_data": {
            "length": 3,
            "set_length": 6,
            "numbers": 1,
            "uppercase": 1,
            "separator": "-"
        },
        "auto_generated": True  # Flag to show this was auto-generated
    })


@app.post("/generate", response_class=HTMLResponse)
async def generate_password(
    request: Request,
    length: int = Form(3, ge=1, le=10),
    set_length: int = Form(6, ge=3, le=20),
    numbers: int = Form(1, ge=0),
    uppercase: int = Form(1, ge=0),
    separator: str = Form("-")
):
    """Generate a password based on form input"""
    try:
        # Validate separator
        if len(separator) > 3:
            raise ValueError("Separator must be 3 characters or less")
        
        # Generate the password
        password = superset(
            length=length,
            set_length=set_length,
            numbers=numbers,
            uppercase=uppercase,
            separator=separator
        )
        
        return templates.TemplateResponse("index.html", {
            "request": request,
            "generated_password": password,
            "form_data": {
                "length": length,
                "set_length": set_length,
                "numbers": numbers,
                "uppercase": uppercase,
                "separator": separator
            },
            "success_message": "Password generated successfully!"
        })
        
    except ValueError as e:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "generated_password": None,
            "form_data": {
                "length": length,
                "set_length": set_length,
                "numbers": numbers,
                "uppercase": uppercase,
                "separator": separator
            },
            "error_message": str(e)
        })


@app.get("/api/generate")
async def api_generate_password(
    length: int = 3,
    set_length: int = 6,
    numbers: int = 1,
    uppercase: int = 1,
    separator: str = "-"
):
    """API endpoint for generating passwords (JSON response)"""
    try:
        password = superset(
            length=length,
            set_length=set_length,
            numbers=numbers,
            uppercase=uppercase,
            separator=separator
        )
        
        return {
            "password": password,
            "parameters": {
                "length": length,
                "set_length": set_length,
                "numbers": numbers,
                "uppercase": uppercase,
                "separator": separator
            }
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
