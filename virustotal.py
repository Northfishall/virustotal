import urllib3
import os
import json
import time
import random

API_KEY = "defb5a6313cd911f06612f2fceed1ee5e6077e8e21ad2e80ef08987e5eaeceba"
sample_path = "../malware_sample/sha1/"
analyses_path = "./old_report/"
http = urllib3.PoolManager()

#读取json文件
def load_json(path):
    with open (path,'r') as f :
        data = json.load(f)
        return data

#存储dict 到json文件中
def sotre_json(path,data):
    with open (path,'w') as f :
        json.dump(data,f)

def request_vt(url):
    result = http.request(method = "GET", url = url, headers = {'x-apikey': API_KEY})
    #return result.data.decode("UTF-8")
    return result


def download_by_id():
    null = "NULL"
    index = 1
    reportid_path = "./analyses/"
    analyses_url = "https://www.virustotal.com/api/v3/analyses/{}"
    save_path_form = "./old_report/{}.json"
    files = os.walk(reportid_path)
    for path, dir_list , file_list in files :
        for file_name in file_list:
            if index < 415:
                index +=1
                continue
            id_file_path = os.path.join(path,file_name)
            id_json = load_json(id_file_path)
            report_id = id_json['data']['id']
            report_name = id_json['meta']['file_info']['md5']
            url = analyses_url.format(str(report_id))
            save_path = save_path_form.format(str(report_name))
            result = request_vt(url)
            sotre_json(save_path,eval(result.data.decode("UTF-8")))
            time.sleep(random.randint(25,60))




def submite_file():
    name_id = dict()
    files = os.walk(sample_path)
    save_path = "./name_id.json"
    null = "NULL"
    for path, dir_list , file_list in files :
        for file_name in file_list:
            file_path = os.path.join(path,file_name)
            print(file_name)
            print(name_id)
            with open(file_path,'rb') as f :
                file_data = f.read()
                id_result = http.request(method = "POST", url = "https://www.virustotal.com/api/v3/files",headers = {'x-apikey': API_KEY,"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36"}, fields = {'file':( file_name,file_data)})
                id = eval(id_result.data.decode("UTF-8"))["data"]["id"]
                name_id[file_name] = id
                sotre_json(save_path,name_id)
            time.sleep(random.randint(15,35))

def get_file():
    files = os.walk(sample_path)
    analyses_url = "https://www.virustotal.com/api/v3/analyses/{}"
    #save_path = "./analyses/{}.json"
    save_path = "./report/{}.json"
    null = "Null"
    for path, dir_list , file_list in files :
        for file_name in file_list:
            file_path = os.path.join(path,file_name)
            print(file_name)
            with open(file_path,'rb') as f :
                file_data = f.read()
                id_result = http.request(method = "POST", url = "https://www.virustotal.com/api/v3/files",headers = {'x-apikey': API_KEY,"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36"}, fields = {'file':( file_name,file_data)})
                id = eval(id_result.data.decode("UTF-8"))["data"]["id"]
                print(id)
                result_url = analyses_url.format(str(id))
                print(result_url)
                while 1:
                    result = request_vt(result_url)
                    #result = http.request(method = "GET" ,url = analyses_url.format(str(id)), headers = {'x-apikey':API_KEY} )
                    if result.status == 200:
                        save_file_path = save_path.format(str(file_name))
                        result_data = eval(result.data.decode("UTF-8"))
                        print(result_data)
                        if result_data['data']['attributes']['results'] == {}:
                            print("fail, will retry")
                            time.sleep(random.randint(30,60))
                        else:
                            sotre_json(save_file_path,result_data)
                            print("成功")
                            break
                        # with open(file_path,"w") as f:
                        #     print(type(eval(result.data.decode("UTF-8"))))
                        #     json.dump(eval(result.data.decode("UTF-8")),f)
                        #     print("成功写入")
                    else:
                        print("失败")
                    time.sleep(random.randint(10,30))
                    
            f.close()
            time.sleep(random.randint(20,40))


def check_result():
    files = os.walk(analyses_path)
    for path,dir_list, file_list in files:
        for file_name in file_list:
            file_path = os.path.join(path,file_name)
            data = load_json(file_path)
            label = data["data"]['attributes']["results"]
            print(label)
            AV_result = []
            split_result = []
            frequence = dict()
            for key in label:
                AV_result.append(label[key])
            for AV in  AV_result:
                temp = AV.split(".")
                print(temp)
                for key in temp:
                    if key in frequence:
                        frequence[key] += 1
                    else:
                        frequence[key] = 1
            print(frequence)
            break
            

def test():
    #url = "https://www.virustotal.com/api/v3/analyses/ZTFkM2ZkYWNiM2QzZjNhMDRiYjc0MTM3ZDAxNDhlZTc6MTU5OTU1NDI5MA=="
    url = "https://www.virustotal.com/api/v3/sigma_analyses/ZTFkM2ZkYWNiM2QzZjNhMDRiYjc0MTM3ZDAxNDhlZTc6MTU5OTU1NDI5MA=="
    result = http.request(method = "GET" ,url = url, headers = {'x-apikey':API_KEY} )
    print(result.data.decode("UTF-8"))

if __name__ == "__main__":
    #get_file()
    #test()
    # check_result()
    download_by_id()
    # null = "Null"
    # sotre_json('./test2.json',eval(request_vt("https://www.virustotal.com/api/v3/analyses/MjdhZDU5NzE5MzNkNTE0YzNhMGU5MGZlMmEwZjAzODk6MTU5OTgxMjQ0OA==")))
    #submite_file()