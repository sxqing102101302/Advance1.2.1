#这份是后端接口文件
from flask import Flask,jsonify,request
from flask_cors import CORS
import os
import json

app = Flask(__name__)
CORS(app)


@app.route('/read_json', methods=['POST'])
def read_all_json():
    folder_path = '/home/p4/tutorials/exercises/load_balance_/record_file/' 
    all_data = []

    try:
        for file_name in os.listdir(folder_path):
            if file_name.endswith('.json'):
                file_path = os.path.join(folder_path, file_name)
                with open(file_path, 'r') as file:
                    json_data = file.read()
                    data = json.loads(json_data)
                    data['file_name'] = os.path.splitext(file_name)[0]  
                    all_data.append(data)
        test_list = [all_data]  # 将 all_data 包装成一个数组，并命名为 test_list
        return jsonify({'test_list': test_list})
    except FileNotFoundError:
        return jsonify({'error': 'File not found'})
    except Exception as e:
        return jsonify({'error': str(e)})



if __name__ == '__main__':
    app.run()
