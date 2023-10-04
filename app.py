# -*- coding: utf-8 -*-
"""
Created on Tue Nov 17 21:40:41 2020

@author: win10
"""

# 1. Library imports
import uvicorn
from fastapi import FastAPI, File, UploadFile
from SystemLogs import SystemLogs
import numpy as np
import pickle
import pandas as pd
import joblib
# 2. Create the app object
app = FastAPI()



pickle_in2 = open("modeltree.pkl","rb")
model_ware = pickle.load(pickle_in2)


# 3. Index route, opens automatically on http://127.0.0.1:8000
@app.get('/')
def index():
    return {'message': 'Hello, World'}

# 4. Route with a single parameter, returns the parameter within a message
#    Located at: http://127.0.0.1:8000/AnyNameHere
@app.get('/{name}')
def get_name(name: str):
    return {'Welcome To Krish Youtube Channel': f'{name}'}

# 3. Expose the prediction functionality, make a prediction from the passed
#    JSON data and return the predicted Bank Note with the confidence

@app.post('/predict_malware')
async def predict_malware(file: UploadFile):
    with open(file.filename, "wb") as f:
        f.write(file.file.read())

    # print(classifier.predict([[variance,skewness,curtosis,entropy]]))
    new_log_data = pd.read_csv(file.filename)
    cols="""duration,
        protocol_type,
        service,
        flag,
        src_bytes,
        dst_bytes,
        land,
        wrong_fragment,
        urgent,
        hot,
        num_failed_logins,
        logged_in,
        num_compromised,
        root_shell,
        su_attempted,
        num_root,
        num_file_creations,
        num_shells,
        num_access_files,
        num_outbound_cmds,
        is_host_login,
        is_guest_login,
        count,
        srv_count,
        serror_rate,
        srv_serror_rate,
        rerror_rate,
        srv_rerror_rate,
        same_srv_rate,
        diff_srv_rate,
        srv_diff_host_rate,
        dst_host_count,
        dst_host_srv_count,
        dst_host_same_srv_rate,
        dst_host_diff_srv_rate,
        dst_host_same_src_port_rate,
        dst_host_srv_diff_host_rate,
        dst_host_serror_rate,
        dst_host_srv_serror_rate,
        dst_host_rerror_rate,
        dst_host_srv_rerror_rate"""
    columns=[]
    for c in cols.split(','):
        if(c.strip()):
            columns.append(c.strip())

    columns.append('target')
    attacks_types = {
    'normal': 'normal',
    'back': 'dos',
    'buffer_overflow': 'u2r',
    'ftp_write': 'r2l',
    'guess_passwd': 'r2l',
    'imap': 'r2l',
    'ipsweep': 'probe',
    'land': 'dos',
    'loadmodule': 'u2r',
    'multihop': 'r2l',
    'neptune': 'dos',
    'nmap': 'probe',
    'perl': 'u2r',
    'phf': 'r2l',
    'pod': 'dos',
    'portsweep': 'probe',
    'rootkit': 'u2r',
    'satan': 'probe',
    'smurf': 'dos',
    'spy': 'r2l',
    'teardrop': 'dos',
    'warezclient': 'r2l',
    'warezmaster': 'r2l',
    }
    df = pd.read_csv(new_log_data,names=columns)
    df['Attack Type'] = df.target.apply(lambda r:attacks_types[r[:-1]])
    df = df.drop(['target'], axis=1)
    return {
        'prediction': df
    }


# 5. Run the API with uvicorn
#    Will run on http://127.0.0.1:8000
if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=3000)
    
#uvicorn app:app --reload