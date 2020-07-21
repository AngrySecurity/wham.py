"""Begin license text (for otherwise unlicensesd content)
The MIT License (MIT)

Copyright 2020 Angry Security LLC. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy 
of this software and associated documentation files (the "Software"), to deal 
in the Software without restriction, including without limitation the rights 
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
copies of the Software, and to permit persons to whom the Software is 
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
End license text."""


"""Begin license text (for useage of Python Requests & Requests-html libraries)
The MIT License (MIT)

Copyright 2018 Kenneth Reitz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
End license text."""


"""Begin license text (for useage of Python Selenium libraries)
Copyright 2020 Software Freedom Conservancy (SFC)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
End license text."""



#banner & usage
print('*****************************************')
print('****************wham.py******************')
print('*****************************************')
print('info: open-source threat hunting tool used to monitor static web page content for risk associated with embedded HTML hyperlinks and absolute URLs')
print()
print('*****************************************')
print()

#import libs
import requests
from requests_html import HTMLSession
from selenium import webdriver
import time
import sys
import urllib3

#disable SSL cert warning 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#config VT params 
api_key='<INSERT VT API key>'
vturl = 'https://www.virustotal.com/vtapi/v2/url/report'

#config Requests & Requests-html User-Agent to reflect Chrome
hdrs = {'User-Agent': 'Chrome/70.0.3538.77'}

#input: user provided static url/web page
url = input('Enter the URL of the static webpage (e.g. https://www.angrysecurity.com): ')
print()
print('-----> Ok, you entered:', url)
print()

#fn: user continuance check
def carryon():
	yorn = input('>---------------Continue? (enter \"y/n\"): ')
	if yorn != 'y':
		print("Exiting....")
		time.sleep(1) 
		sys.exit(1)
	print()
	
#create lists
initlist=[]
init2list=[]
comblist=[]
listofurls=[]

#use Requests-html lib to verify provided URL is accessible (view error msgs as required)
print()
print()
print('Step 1/4:  About to connect to static webpage URL...') 
print()
carryon()
try:
	session = HTMLSession()
	wpobj = session.get(url, headers=hdrs, timeout=10, verify=False)
except:
	print('error establishing session with provided URL')
try:
	print('-----> Server response: ',wpobj.status_code)
	content_type = wpobj.headers['Content-Type'].lower()
	print('-----> Server content:  ', content_type)
	if wpobj.history:
		print('-----> *Webpage entered redirects to:   ',wpobj.url)
		print('----------> ...main URL updated (continuing)')
		url = wpobj.url #update test URL to redirected URL
	if wpobj.status_code == 200 and content_type is not None and content_type.find('html') > -1:
		print()
	else:
		print('error - improper content /(html/) or response type /(non-200/)')
	for b in wpobj.html.absolute_links:	
		if "//" in b:		#filter for absolute links 
			initlist.append(b)		#capture resiults in list
except:
	print('error translating server response')
	print()
	print("Exiting now....")
	time.sleep(1) 
	sys.exit(1)


#use Selenium + ChromeDriver to open webpage and render JS -- document any additional absolute links
print()
print()
print('Step 2/4:  About to render the URL with a headless browser to record any additional href URLs observed...')
print()
carryon()
print('...this may take a min...')
print()
#config Selenium ChromeDriver options
options = webdriver.ChromeOptions()
options.add_argument('--ignore-certificate-errors')
options.add_argument('--incognito')
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')
driver = webdriver.Chrome(chrome_options=options)
#run Selenium and annotate hrefs
try:
	driver.set_page_load_timeout(10)
	driver.get(url)
	driver.execute_script("window.scrollTo(0,document.body.scrollHeight);")	#scroll to bottom of page
except:
	print('error retrieving webpage')
	print('...Exiting')
	driver.close()
	sys.exit(2)
try:
	elems = driver.find_elements_by_xpath("//a[@href]")		#use XPath to search for anchor elements with href tags
except:
	print('error retrieving anchor tags/hrefs')
	print('...Exiting')
	driver.close()
	sys.exit(2)
for elem in elems:		#extract string/URL from "href" atrribute
	e = elem.get_attribute("href")
	init2list.append(e)	
	
	
#combine lists, parse for absolute links, & dedupe
comblist = initlist + init2list
for n in comblist:		
	if '//' in n:
		n2 = n.rstrip('/')	
		listofurls.append(n2)	
listofurls = list(dict.fromkeys(listofurls))	
print()
print('===============> Number of links found wihtin the webpage: ', len(listofurls))
print()
print()


#use Requests to verify ea additional site is up + annotate any redirects, as found
print('Step 3/4: About to verify if each link is accessible and if redirects are observed ...')
print()
carryon()
print('...this may take a min...')
print()
j = 0
count = len(listofurls)
while j < count:
	a = listofurls[j]
	j += 1
	print('URL #%s: %s' % (j, a))
	try:
		resp = requests.get(a, headers=hdrs, timeout=5, verify=False)
		time.sleep(1)	#pause 1 sec between each request to attempt to avoid potential auto-blacklisting
		respurl = resp.url.rstrip('/')
		if resp.history:
			i = 1
			for rsp in resp.history:
				rspurl = rsp.url.rstrip('/')	
				if respurl != rspurl:
					if a != rspurl:
						print('>----rdr%s: %s' % (i, rspurl))
						listofurls.append(rspurl)			
						i += 1
			if respurl != a:
				print(">----------final: ", respurl)
				listofurls.append(respurl)
	except:
		print('--error retrieving website')
print()
listofurls = list(dict.fromkeys(listofurls))	#list cleanup (dedupe)
print('===============> TOTAL # links (including redirections): ', len(listofurls))

#use VT Public API to retrieve URL scores
print()
print()
print('Step 4/4:  About to generate risk scores for each URL using VirusTotal\'s Public API...')
carryon()
print()
print('...this may take a few min...')
print()
for lurl in listofurls:
	params = {'apikey': api_key, 'resource': lurl }
	wpobj2 = requests.get(vturl, params=params)
	wpobj2_json = wpobj2.json()
	try:
		if wpobj2_json['response_code'] !=0:
			print(lurl)
			print('----risk score: %s/%s' % (wpobj2_json['positives'], wpobj2_json['total']))
			time.sleep(15)	#ensure 15 second timeout to adhere to Public API restrictions of 4 requests per minute
		else:
			print(lurl)
			print('*no score (site not in VT db)')
			time.sleep(15)	#ensure 15 second timeout to adhere to Public API restrictions of 4 requests per minute
	except:
		print('*site unresponsive or provided abnormal reponse....')
print()
print()
print()
print('*************script complete*************')
