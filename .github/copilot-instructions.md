# AI Agent Instructions for Python Learning Codebase

## Project Overview
This is a Python learning codebase organized by dates, containing various practice exercises and examples. The code is structured into daily folders (e.g., `10-22-2025`, `10-23-2025`, `10-28-2025`), each focusing on different programming concepts.

## Code Organization
- Daily folders contain independent Python scripts
- Each script focuses on a specific concept or pattern
- No external dependencies or complex project setup required

## Key Patterns and Conventions

### Input Handling
- Most scripts use `input()` for user interaction
- Input validation is straightforward, using if-else conditions
- Example: See `10-23-2025/login1.py` for username/password handling

### Control Flow Patterns
1. Basic if-else:
```python
# Example from marks.py
if marks >= 90: 
    print("Excellent")
elif marks >= 70:
    print("Good")
```

2. Nested conditionals:
```python
# Example from admission.py
if percentage >= 60 and math_marks >= 50: 
    print("You are eligible for admission.")
```

### Pattern Printing
- Extensive use of nested while loops for pattern generation
- Common variable names: `i` for outer loop, `j` for inner loop
- Pattern types include:
  - Square patterns (`square.py`)
  - Triangles (`righttriangle.py`)
  - Pyramids (`pyramid.py`)
  - Hollow shapes (`hollow1.py`)

### Math Operations
- Simple calculations using basic operators
- Power operations use `**` operator
- Example: `cube.py` for calculating cube of numbers

## Development Workflow
1. Scripts are standalone - no imports between files
2. Each script can be run independently with Python interpreter
3. Test by providing different inputs through console

## Best Practices to Follow
1. Use descriptive variable names for input values
2. Include user prompts for all input() calls
3. Format output messages clearly
4. Maintain consistent indentation (4 spaces)
5. Use while loops for pattern printing
6. Handle basic input validation where necessary

## File Navigation
- Key examples:
  - Basic math: `10-22-2025/p1.py`
  - Login flow: `10-23-2025/login1.py`
  - Pattern printing: `10-28-2025/pyramid.py`
  - Decision making: `10-23-2025/grading.py`