def calculate(m1, m2, m3):
    average = (m1 + m2 + m3) / 3 
    
    if average >= 90: 
        grade = "A"
    elif average >= 80: 
        grade = "B"
    elif average >= 70: 
        grade = "C"
    elif average >= 60:
        grade = "D"
    else: 
        grade = "F"
        
    return average, grade

avg, grd = calculate(100, 94, 89)
print("Average: ", avg)
print("Grade: ", grd)