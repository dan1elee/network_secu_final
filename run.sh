cd receiver/ && make
cd ..
cd sender/ && make
cd ..
if [ ! -d "tmp" ]; then
  mkdir tmp
  echo "tmp 文件夹已创建。"
else
  echo "tmp 文件夹已存在。"
fi
pip install streamlit
streamlit run st_page/主页.py