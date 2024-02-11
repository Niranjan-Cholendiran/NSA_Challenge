import pandas as pd
import numpy as np

import warnings
# Suppress all warnings
warnings.filterwarnings("ignore")

# Your code here

input_file_loc='netflows.txt'
# Assuming your file is tab-separated
df = pd.read_csv(input_file_loc, delimiter=" ", header=None, dtype=str)
df_for_final1= df.copy()


def initialize(df):
    def hex_to_decimal(hex_string):
        if type(hex_string) == type(int):
            return
        return int(hex_string, 16)
    def hex_ip_port(hex_value):
        first=hex_value.split(".")[0]
        second=hex_value.split(".")[1]
        #print(firs)
        
        left=0
        right=1
        ans=[]
        while right<len(first):
            f=first[left]
            n=first[right]
            g=f+n
            
            
            ans.append(str(hex_to_decimal(g)))
            left=left+2
            right=right+2
        return ".".join(ans),str(hex_to_decimal(second))

    df[0] = df[0].str.rstrip(':')
    df["Date"]=pd.to_datetime(df[0].apply(hex_to_decimal),unit="s")
    df["pr"]=df[1].astype(str)
    source=df[2].apply(hex_ip_port)
    df["source_ip"]=[i[0]for i in source]
    df["source_port"]=[i[1]for i in source]
    des=df[3].apply(hex_ip_port)
    df["destination_ip"]=[i[0]for i in des]
    df["destination_port"]=[i[1]for i in des]
    df["cnt"]=df[4].apply(hex_to_decimal)
    df["bts"]=df[5].apply(hex_to_decimal)
    df["Flag"]=df[6]
    df=df.drop([0,1,2,3,4,5,6],axis=1)

    for i in (df.index):
        if df['source_port'][i] == "22":
            df['source_port'][i] = df['destination_port'][i]
            df['destination_port'][i] = "22"
            temp = df['source_ip'][i]
            df['source_ip'][i] = df['destination_ip'][i]
            df['destination_ip'][i] = temp
    df[(df['source_port'] == "22") & (df['destination_port'] == "22")]


    return df


df = initialize(df)
df_for_final2= df.copy()

def checkInterval(x):
    if len(x) <= 2:
        return None
    x.sort_values('Date', inplace = True)
    #x.reset_index(drop = True, inplace = True)
    intervals = []
    intervals = np.diff(x["Date"])
    intervals = pd.Series(intervals)
    return np.std(intervals.dt.total_seconds())

grouped_df= df.groupby(by=['source_ip','destination_ip']).agg({'cnt':'mean', 'bts':'max', 'Date':'len', 'Date':lambda x:(max(x)-min(x)).total_seconds()/60}).reset_index()
grouped_df.columns = ['source_ip','destination_ip','avg_cnt','max_bts','date_range_min']
grouped_df


grouped_df['std']= df.groupby(by=['source_ip','destination_ip']).apply(checkInterval).values
grouped_df.fillna(grouped_df['std'].mean(), inplace= True)
grouped_df.head()


#### 1. SSH Attacker Malicious IP List

# From the text file

with open('ssh_m1.txt', 'r') as file:
    ip_addresses = []
    
    for line in file:
        ip_address = line.split(':')[1].strip()
        ip_addresses.append(ip_address)

# Print the list of IP addresses
#print(ip_addresses)
ip_addresses1= ip_addresses[1:]


# From the php/txt file in dataframe fromat
with open('ssh_m2.txt', 'r') as file:
    ip_addresses = []
    
    for line in file:
        if not line.startswith('#'):
            break
    
    for line in file:
        ip_address = line.split()[0].strip()
        
        ip_addresses.append(ip_address)

ip_addresses2= ip_addresses[1:]


import json

with open('ssh_m3.json', 'r') as file:
    data = json.load(file)
    
    ip_addresses = []
    
    for entry in data:
        ip_address = entry['ip']
        
        ip_addresses.append(ip_address)

ip_addresses3= ip_addresses

malicious_ips = ip_addresses1 + ip_addresses2 + ip_addresses3
len(malicious_ips)


ip_with_r= df[df['Flag']=='SR']['source_ip'].unique()

malicious_ips_new= malicious_ips+ list(ip_with_r)


lst = df['source_ip'].unique()

def ip_int(ip):
    if "." not in ip:
        return np.nan 
    return int(ip.replace(".",""))

remote_ips= []
for ip in lst:
    curr= ip_int(ip)
    if 1286100 <= curr <= 12861255255:
        remote_ips.append(ip)
    elif 13020700 <= curr <= 130207255255:
        remote_ips.append(ip)
    elif 14321500 <= curr <= 143215255255:
        remote_ips.append(ip)
    elif 192761810 <= curr <= 19276181255:
        remote_ips.append(ip)
    else:
        continue





grouped_df['remote_flag']= grouped_df['source_ip'].isin(remote_ips)

def hard_code_flags (source_ip):
    if source_ip in malicious_ips_new:
        return True 
    else:
        return False

grouped_df['malicious_flag']= grouped_df['source_ip'].apply(hard_code_flags)

final_grouped_data_1= grouped_df[grouped_df['malicious_flag']==True][['source_ip','destination_ip','malicious_flag']]


grouped_df = grouped_df[grouped_df['malicious_flag']==False]

grouped_df.drop(columns=['malicious_flag'], inplace= True)


source_destination_ip= grouped_df[['source_ip','destination_ip']]


modeling_data= grouped_df.drop(columns= ['source_ip','destination_ip'])


modeling_data['remote_flag']= modeling_data['remote_flag'].apply(lambda x: 1 if x else 0)


# Model Prediction

import pickle

model_path = 'final_model.pkl'

# Load the saved model from the pickle file
with open(model_path, 'rb') as file:
    loaded_model = pickle.load(file)


y_pred = loaded_model.predict(modeling_data)



source_destination_ip['malicious_flag']= y_pred

final_grouped_data_2 = pd.concat([final_grouped_data_1, source_destination_ip], ignore_index=True)


# Join with the input dataset



merged_df = pd.merge(df_for_final2, final_grouped_data_2, how='left', on=['source_ip','destination_ip'])


merged_df['malicious_flag'].fillna(0, inplace=True)

df_for_final1['malicious_flag']=merged_df['malicious_flag']

df_for_final1.to_csv('results.csv', index=False)
