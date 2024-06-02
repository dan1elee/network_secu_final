import pandas as pd
import streamlit as st
import plotly.graph_objs as go

st.set_page_config(
    page_title="数据展示",
    page_icon="📈",
    layout="wide")
aes_data = pd.read_csv('./st_page/data/AES_data.csv')
des_data = pd.read_csv('./st_page/data/DES_data.csv')
rsa_data = pd.read_csv('./st_page/data/RSA_data.csv')

key_traces = []
encrypt_traces = []
decrypt_traces = []
total_traces = []

aes_grouped = aes_data.groupby('key_length')
aes_split = {key: group for key, group in aes_grouped}
for key_length, df_key in aes_split.items():
    key_gen_trace = go.Scatter(
        x=df_key['file_length'],
        y=df_key['key_gen_time'],
        mode="lines+markers",
        name=f"AES算法，密钥长度{key_length}"
    )
    key_traces.append(key_gen_trace)
    encrypt_trace = go.Scatter(
        x=df_key['file_length'],
        y=df_key['encrypt_time'],
        mode="lines+markers",
        name=f"AES算法，密钥长度{key_length}"
    )
    encrypt_traces.append(encrypt_trace)
    decrypt_trace = go.Scatter(
        x=df_key['file_length'],
        y=df_key['decrypt_time'],
        mode="lines+markers",
        name=f"AES算法，密钥长度{key_length}"
    )
    decrypt_traces.append(decrypt_trace)
    total_trace = go.Scatter(
        x=df_key['file_length'],
        y=df_key['total_time'],
        mode="lines+markers",
        name=f"AES算法，密钥长度{key_length}"
    )
    total_traces.append(total_trace)

des_grouped = des_data.groupby('key_length')
des_split = {key: group for key, group in des_grouped}
for key_length, df_key in des_split.items():
    encrypt_trace = go.Scatter(
        x=df_key['file_length'],
        y=df_key['encrypt_time'],
        mode="lines+markers",
        name=f"DES算法，密钥长度{key_length}"
    )
    encrypt_traces.append(encrypt_trace)
    decrypt_trace = go.Scatter(
        x=df_key['file_length'],
        y=df_key['decrypt_time'],
        mode="lines+markers",
        name=f"DES算法，密钥长度{key_length}"
    )
    decrypt_traces.append(decrypt_trace)
    total_trace = go.Scatter(
        x=df_key['file_length'],
        y=df_key['total_time'],
        mode="lines+markers",
        name=f"DES算法，密钥长度{key_length}"
    )
    total_traces.append(total_trace)


gen_fig = go.Figure(data=key_traces, layout={
    "xaxis_title": "文件长度(Byte)",
    "yaxis_title": "时间(ms)",
})
st.write(f'- 密钥生成时间')
st.plotly_chart(gen_fig, use_container_width=True)

encrypt_fig = go.Figure(data=encrypt_traces, layout={
    "xaxis_title": "文件长度(Byte)",
    "yaxis_title": "时间(ms)",
})
st.write(f'- 加密时间')
st.plotly_chart(encrypt_fig, use_container_width=True)

decrypt_fig = go.Figure(data=decrypt_traces, layout={
    "xaxis_title": "文件长度(Byte)",
    "yaxis_title": "时间(ms)",
})
st.write(f'- 解密时间')
st.plotly_chart(decrypt_fig, use_container_width=True)

total_fig = go.Figure(data=total_traces, layout={
    "xaxis_title": "文件长度(Byte)",
    "yaxis_title": "时间(ms)",
})
st.write(f'- 总时间')
st.plotly_chart(total_fig, use_container_width=True)

rsa_enc_trace = go.Scatter(
    x=rsa_data['key_length'],
    y=rsa_data['encrypt_time'],
    mode="lines+markers",
    name=f"RSA算法加密时间"
)

rsa_dec_trace = go.Scatter(
    x=rsa_data['key_length'],
    y=rsa_data['decrypt_time'],
    mode="lines+markers",
    name=f"RSA算法解密时间"
)

rsa_crypt_fig = go.Figure(data=[rsa_enc_trace, rsa_dec_trace], layout={
    "xaxis_title": "密钥长度(bit)",
    "yaxis_title": "时间(us)",
})
rsa_crypt_fig.update_layout(
    yaxis=dict(type='log')
)
st.write(f'- RSA算法')
st.plotly_chart(rsa_crypt_fig, use_container_width=True)