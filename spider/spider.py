from .__version__ import __version__
import subprocess
import json
import os
from urllib.parse import urlparse
from b_hunters.bhunter import BHunters
from karton.core import Task
import shutil
import re
from bson.objectid import ObjectId

class spider(BHunters):
    """
    B-Hunters-GoSpider developed by 0xBormaa
    """

    identity = "B-Hunters-GoSpider"
    version = __version__
    persistent = True
    filters = [
        {
            "type": "url", "stage": "new"
        },
        {
            "type": "path", "stage": "new"
        }
        ,
        {
            "type": "subdomain", "stage": "new"
        }
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
                    
    def scan(self,url):        
        result,resultunique,spiderfullresults=self.spidercommand(url)
        
        return result,resultunique,spiderfullresults
    def spidercommand(self,newurl):
        result=[]
        resultunique=[]
        spiderfullresults=[]

        try:
            folder1=self.generate_random_filename()
            folder2=self.generate_random_filename()

            url=self.add_https_if_missing(newurl)
            output = subprocess.run(["/app/spider.sh", url, folder1, folder2], capture_output=True, text=True, timeout=900)
            data=output.stdout.split("\n")
            try:
                
                # Open the file in read mode
                with open(folder2+"/output.txt", "r") as file:
                    # Read the contents of the file
                    file_contents = file.read()
                    data=file_contents.split("\n")
                    result=data
            except Exception as e:
                self.log.error(e)
                
            try:
                
                # Open the file in read mode
                with open(folder2+"/uniqueurls.txt", "r") as file:
                    # Read the contents of the file
                    file_contents = file.read()
                    data=file_contents.split("\n")
                    resultunique=data
            except Exception as e:
                self.log.error(e)
            try:
                # Open the file in read mode
                with open(folder2+"/spiderall.json", "r") as file:
                    # Read the contents of the file
                    for line in file:
                        try:
                            
                            # Strip any extra whitespace from the line
                            line = line.strip()
                            # break
                            if line:  # Check if the line is not empty
                                # Parse the JSON data and append it to the list
                                data = json.loads(line)
                                # print(data)
                                if "http" in data["output"]:

                                    spiderfullresults.append(data["output"].strip('"'))
                        except Exception as e:
                            if "http" in line:
                                spiderfullresults.append(line.split("- ")[-1].strip('"'))

            except FileNotFoundError:
                print("File not found.")
            except IOError as e:
                print("Error:", e)
                

            shutil.rmtree(folder1)
            shutil.rmtree(folder2)

        except Exception as e:
            print("error ",e)
            # result=[]
        return result,resultunique,spiderfullresults
    
    def process(self, task: Task) -> None:
        source=task.payload["source"]
        url = task.payload["data"]
        domain = task.payload["subdomain"]
        db=self.db
        report_id=task.payload_persistent["report_id"]    
        scan_id=task.payload_persistent["scan_id"]
        
        try:
                
            self.log.info("Starting processing new url")
            self.log.warning(url)
            domain = re.sub(r'^https?://', '', domain)
            domain = domain.rstrip('/')
            self.update_task_status(domain,"Started")
            result,resultunique,spiderfullresults=self.scan(url)
            self.waitformongo()
            db=self.db
            urlstripped = re.sub(r'^https?://', '', url)
            urlstripped = urlstripped.rstrip('/')
            spiderfullresults = list(set(spiderfullresults))
            collection = db["links"]
            existing_document = collection.find_one({"report_id":ObjectId(report_id),"source":self.identity})
            new_links=[]
            if existing_document:
                existing_links = existing_document.get("Links", [])
                new_links = [link for link in spiderfullresults if link not in existing_links]
            else:
                new_links=spiderfullresults
            if new_links !=[] and new_links!=[url]:
                resultdata = "\n".join(map(lambda x: str(x), new_links)).encode()
                self.log.info("Uploading data of "+url)
                senddata=self.backend.upload_object("bhunters","spider_"+scan_id+"_"+self.encode_filename(urlstripped),resultdata)
                
                collection.update_one({"report_id": ObjectId(report_id),"source":self.identity}, {"$push": {f"Links": {"$each": new_links}}},upsert=True)
                tag_task = Task(
                    {"type": "paths", "stage": "scan"},
                    payload={"data": urlstripped,
                            "subdomain":domain,
                    "source":"spider",
                    "type":"file"
                    }
                )
                self.send_task(tag_task)


            if result !=['']:
                
                
                # update_result = collection.update_one({"Domain": domain}, {'$push': {'Vulns': result}})
                self.send_discord_webhook("Spider found new vulns for "+domain,result,"main")
            collection = db["domains"]

            jsdata=[]
            for i in resultunique:
                
                if ".js" in i and i !="":
                    
                    try:
                        if self.checkjs(i):

                            collection2 = db["js"]
                            existing_document = collection2.find_one({"report_id":ObjectId(report_id),"url": i})
                            if existing_document is None:
                                jsdata.append(i)
                                tag_task = Task(
                                    {"type": "js", "stage": "new"},
                                    payload={"data": url,
                                    "subdomain":domain,
                                    "file": i,
                                    "module":"spider"
                                    }
                                )
                                self.send_task(tag_task)
                    except Exception as e:
                        raise Exception(e)
            uniquespider=list(set(spiderfullresults))
            for i in uniquespider:
                if ".js" in i and i not in jsdata:
                    
                    try:
                        if self.checkjs(i):

                            collection2 = db["js"]
                            existing_document = collection2.find_one({"report_id":ObjectId(report_id),"url": i})
                            if existing_document is None:
                                tag_task = Task(
                                    {"type": "js", "stage": "new"},
                                    payload={"data": url,
                                    "subdomain":domain,
                                    "file": i,
                                    "module":"spider"
                                    }
                                )
                                self.send_task(tag_task)
                    except Exception as e:
                        self.log.error(e)
            self.update_task_status(domain,"Finished")

        except Exception as e:
            self.update_task_status(domain,"Failed")
            raise Exception(e)
