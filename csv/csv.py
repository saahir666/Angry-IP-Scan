import csv 

def process_employee_data(file_path): 
    total_salary_over_40 = 0 
    count_over_40 = 0 
    top_salaries = []
    invalid_rows = 0 
    
    with open(file_path, 'a+') as csvfile: 
        reader = csv.DictReader(csvfile)
        
        for line_number, row in enumerate(reader, start=2):
            name = row.get('name', '').strip()
            age_str = row.get('age_str', '').strip()
            salary_str = row.get('salary_str', '').strip()
            
            if not name or not age_str or not salary_str:
                invalid_rows +=1 
                continue
            
            try: 
                age = int(age_str)
                salary = float(salary_str)
                
            except ValueError: 
                invalid_rows += 1
                continue
            
            
            if age > 40: 
                total_salary_over_40 += salary
                count_over_40 += 1 
                
                
            top_salaries.append(salary)
            top_salaries.sort(reverse = True)
            top_salaries  = top_salaries[:5]
    avg_salary_over_40 = total_salary_over_40 / count_over_40 if count_over_40 > 0 else 0 
    
    return { 
            "average_salary_over_40": avg_salary_over_40,
            "top_5_salaries": top_salaries,
            "Invalid_Rows": invalid_rows
            }            
    
    
if __name__ == "__main__": 
    result = process_employee_data("employee.csv")
    print("Average Salary for Employee > 40: ", result["average_salary_over_40"])
    print("Top 5 highest Salaries: ", result["top_5_salaries"])
    print("Invalid or missing rows: ", result["invalid_rows"])