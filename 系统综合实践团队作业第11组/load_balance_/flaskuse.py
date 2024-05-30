from flask import Flask, make_response, request
from flask_cors import CORS  # 引用CORS，后期需要VUE支持跨域访问会用到
import os


# Flask类只有一个必须指定的参数，即程序主模块或者包的名字，__name__是系统变量，该变量指的是本py文件的文件名
app = Flask(__name__)
# resources全局配置允许跨域的API接口，我们这边为了学习，配置所有，详细学习请百度搜索文档
CORS(app, resources=r'/*')

def solve_string(s):
    s=s.strip()
    s=int(s)
    return s

@app.route('/', methods=['GET', 'POST'])
def add_tag():
    return "hello"


@app.route('/switch_full', methods=['GET', 'POST'])
def switch_full():
    getJson = request.get_json()
    id = str(getJson.get('id'))  # json数据格式
    code=0
    if id==1 or id==6:
        code=0
    else:
        if os.path.exists("./record_file/s6-eth"+id+"_in.json"):
            f=open("./record_file/s6-eth"+id+"_in.json")
            readed=f.readline()
            try:
                readed=solve_string(readed)
            except:
                readed=0
            tcpcount=f.readline()
            try:
                tcpcount=solve_string(tcpcount)
            except:
                tcpcount=0

            udpcount=f.readline()
            try:
                udpcount=solve_string(udpcount)
            except:
                udpcount=0

            ecn_full=f.readline()
            try:
                ecn_full=solve_string(ecn_full)
            except:
                ecn_full=0

            code=ecn_full

        res={
            'code':code
        }
        return res


@app.route('/get_proto', methods=['GET', 'POST'])
def get_proto():
    getJson = request.get_json()
    id = str(getJson.get('id'))  # json数据格式
    id=int(id)
    file=""
    if id==1:
        file="s1-eth1_in"
    elif id<=5:
        file="s"+str(id)+"-eth1_in"
    else :
        file="s"+str(6)+"-eth"+str(id-4)+"_in"


    if os.path.exists("./record_file/"+file+".json"):
        f=open("./record_file/"+file+".json")
        readed=f.readline()
        try:
            readed=solve_string(readed)
        except:
            readed=0
        tcpcount=f.readline()
        try:
            tcpcount=solve_string(tcpcount)
        except:
            tcpcount=0

        udpcount=f.readline()
        try:
            udpcount=solve_string(udpcount)
        except:
            udpcount=0

        ecn_full=f.readline()
        try:
            ecn_full=solve_string(ecn_full)
        except:
            ecn_full=0

        code=ecn_full

    res={
        'udp':udpcount,
        'tcp':tcpcount
    }
    return res


@app.route('/get_flow', methods=['GET', 'POST'])
def get_flow():
    getJson = request.get_json()
    id = str(getJson.get('id'))  # json数据格式
    id=int(id)
    file=""
    if id==1:
        file="s1-eth1_in"
    elif id<=5:
        file="s"+str(id)+"-eth1_in"
    else :
        file="s"+str(6)+"-eth"+str(id-4)+"_in"


    if os.path.exists("./record_file/"+file+".json"):
        f=open("./record_file/"+file+".json")
        readed=f.readline()
        try:
            readed=solve_string(readed)
        except:
            readed=0
        tcpcount=f.readline()
        try:
            tcpcount=solve_string(tcpcount)
        except:
            tcpcount=0

        udpcount=f.readline()
        try:
            udpcount=solve_string(udpcount)
        except:
            udpcount=0

        ecn_full=f.readline()
        try:
            ecn_full=solve_string(ecn_full)
        except:
            ecn_full=0

        data=(udpcount+tcpcount)*1.4

    res={
        'flow':data
    }
    return res


def cal(id):
    file=""
    if id==1:
        file="s1-eth1_in"
    elif id<=5:
        file="s"+str(id)+"-eth1_in"
    else :
        file="s"+str(6)+"-eth"+str(id-4)+"_in"
    if os.path.exists("./record_file/"+file+".json"):
        f=open("./record_file/"+file+".json")
        readed=f.readline()
        try:
            readed=solve_string(readed)
        except:
            readed=0
        tcpcount=f.readline()
        try:
            tcpcount=solve_string(tcpcount)
        except:
            tcpcount=0

        udpcount=f.readline()
        try:
            udpcount=solve_string(udpcount)
        except:
            udpcount=0

        ecn_full=f.readline()
        try:
            ecn_full=solve_string(ecn_full)
        except:
            ecn_full=0
        return tcpcount+udpcount


@app.route('/cal_loss', methods=['GET', 'POST'])
def cal_loss():
    getJson = request.get_json()
    sum=0
    have=0
    sum=cal(1)
    for i in range(2,6):
        have+=cal(i)

    # print(sum)
    # print(have)

    res={
        'loss':max(0,(sum-have)/max(sum,1))
    }
    return res


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081, debug=False, threaded=True)
