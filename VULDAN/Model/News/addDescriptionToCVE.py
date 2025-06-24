import pandas as pd

import openpyxl
dataCve = pd.read_excel('./datasets/News/cve_data.xlsx', sheet_name=0)
descriptions = dataCve['CVEDescription'].values.tolist()
cveID = dataCve['CVEID'].values.tolist()     
# file_pathPositive = 'NewMapping/FinalResultSeperate/Techniqes/AllTechniques.xlsx'
#     # Read the Excel file
# dataTech = pd.read_excel(file_pathPositive, sheet_name=0)
    
# techniquesID = dataTech['TechnqiueID'].values.tolist()
# techniquesDes = dataTech['TechnqiueDescription'].values.tolist()
DataFalsePositives = pd.read_excel('./Results/AttackNewsCVETopk20.xlsx', sheet_name=0, header=None)
arrayDataFalsePositivesWithDes = []

# Iterate through the rows and columns and print each cell
for index, row in DataFalsePositives.iterrows():
    arrayDataRow=[]
    for column, value in row.items():
        if not pd.isna(value):
            if column == 0:
                # for indexdes,technique in enumerate(techniquesID):
                    # if technique == value:
                arrayDataRow.append(value)
                        # arrayDataRow.append(techniquesDes[indexdes])
                # break
            if column > 0:
                for indexCVe, cve in enumerate(cveID):
                    if cve == value:
                        arrayDataRow.append(value)
                        arrayDataRow.append(descriptions[indexCVe])
                        break
            print(f"Row {index + 1}, Column {column}: {value}")
    arrayDataFalsePositivesWithDes.append(arrayDataRow)

# df = pd.DataFrame(arrayDataFalsePositivesWithDes)
        
# # Save to Excel
# df.to_excel('./Results/WeekNewsResultsCVEs.xlsx', index=False)

workbook = openpyxl.Workbook()
sheet = workbook.active
# Iterate through the data and insert each row into successive rows of the Excel sheet
for row_index, row_data in enumerate(arrayDataFalsePositivesWithDes, start=1):
    for column_index, cell_value in enumerate(row_data, start=1):
        sheet.cell(row=row_index, column=column_index, value=cell_value)
workbook.save('./Results/WeekNewsResultsValidation2.xlsx')
workbook.close()
