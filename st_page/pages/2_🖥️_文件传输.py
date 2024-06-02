import streamlit as st
import subprocess
import threading
from time import sleep

def run_snd_program(seed, algo, sha, name):
    result_snd = subprocess.run(['./sender/send',seed, algo, sha, name], capture_output=True, text=True)
    return result_snd.stdout, result_snd.stderr

def run_rcv_program(seed, algo,sha):
    result_rec = subprocess.run(['./receiver/rec', seed, algo, sha], capture_output=True, text=True)
    return result_rec.stdout, result_rec.stderr

def thread1():
    global snd_out, snd_err, filename, algo, sha_value, seed
    snd_out, snd_err = run_snd_program(seed, algo, sha_value, filename)

def thread2():
    global rcv_out, rcv_err, algo, sha_value, seed
    rcv_out, rcv_err = run_rcv_program(seed, algo, sha_value)


if __name__ == '__main__':
    seed_choice = ['RSA', 'DH']
    encrypt_choice = ['AES','DES']
    st.set_page_config(
        page_title="文件传输",
        page_icon="🖥️",
        layout="wide")
    st.title('文件传输')
    filename='./tmp/test_for_st.txt'
    uploaded_file = st.file_uploader('上传用于发送的文件')
    
    if uploaded_file is not None:
        filename = f'./tmp/{uploaded_file.name}'
        with open(filename, 'wb') as f:
            f.write(uploaded_file.getbuffer())
        
        st.success('文件上传完成')
        seed = st.selectbox('选择密钥交换算法', seed_choice)
        algo = st.selectbox('选择加密算法',encrypt_choice)
        sha = st.checkbox('开启SHA-256完整性检验')
        sha_value = "1" if sha else "0"
        if st.button('运行加密传输程序'):
            # snd_out, snd_err = run_snd_program('./tmp/uploaded_file.txt')
            # rec_out, rec_err = run_rcv_program()
            snd_out, snd_err = None, None
            rcv_out, rcv_err = None, None

            t1 = threading.Thread(target=thread1)
            t2 = threading.Thread(target=thread2)

            t1.start()
            sleep(0.05)
            t2.start()

            t1.join()
            t2.join()

            left_column, right_column = st.columns(2)
            with left_column:
                if snd_err != "":
                    st.header("发送端报错！")
                    st.error(snd_err if snd_err is not None else "无法运行")
                st.header("发送端输出：")
                st.text(snd_out if snd_out is not None else "无输出")

            with right_column:
                if rcv_err != "":
                    st.header("接受端报错！")
                    st.error(rcv_err if rcv_err is not None else "无法运行")
                st.header("接收端输出：")
                st.text(rcv_out if rcv_out is not None else "无输出")

    else:
        st.error("请上传文件")

