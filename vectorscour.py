#import argparse for command line args and modules for web scraping and other stuff
import argparse
from urllib.parse import urlparse
import bs4
import requests
from fake_useragent import UserAgent

#set up the functionality for faking user agents
user_agent = UserAgent()

#set up some global variables
args = ""
parsed_target = ""
hostname = ""

#set up the arguments
def get_args():
	parser = argparse.ArgumentParser(description="Find possible vectors of attack by looking at html contents (forms, scripts, etc.)")
	#set up arguments for the target url, the tag to scrape, the depth at which to scrape, and whether or not to restrict scraping to the same site
	#only
	parser.add_argument("target", help="Target URL for scraping.", type=str)
	parser.add_argument("-t", "--type", dest="type", help="Specify the vector to scrape from the url", type=str, required=True)
	parser.add_argument("-d", "--depth", dest="depth", help="Page depth for the scraper.", type=int, required=False)
	parser.add_argument("-ss", "--samesite", dest="samesite", help="Stay on the same site when scraping.", action="store_true", required=False)

	#set some defaults for some of the arguments
	parser.set_defaults(depth=1, samesite=False)

	#get the arguments and return them
	return parser.parse_args()

#a function for getting the contents of a url
def get_contents(url):
	#catch any exceptions for fetching the contents of this url
	try:
		#get the contents of the url with the fake user-agent
		page = requests.get(url, headers={"user-agent": user_agent.chrome})
		#get the html of the request
		html = page.content
		#return the html
		return html
	except:
		print("\n\n" + "*"*30 + "\nCould not fetch contents for:", url + "\n" + "*"*30 + "\n\n")

#function for scraping the web page based on the specified vector
def scrape_vectors(html, depth=None, prevlinks=[]):
	#create the html parser
	soup = bs4.BeautifulSoup(html, "html.parser")

	#find all of the tags that are the same type of tag as the user specified
	vector_tags = soup.find_all(args.type)

	#check to see if we need to scrape anchor urls as well
	if (depth is not None and depth > 1):
		#find all the anchor tags
		anchor_tags = soup.find_all("a")

		#lists for the links and the content of the args.type tags. make sure the vector_tags
		#variable is inside the content list to maintain the contents of the original target url
		#and any other urls we might scrape through recursion
		links = []
		contentlist = [vector_tags]

		#add links to the list
		for anchor in anchor_tags:
			#check to see if there is an href attribute in this anchor tag
			if ("href" in anchor.attrs):
				#create a variable for this
				link = anchor.attrs["href"]
				#check to see that the link is not an empty string and that the link is not in the previous links list
				if (len(link) > 0 and link not in prevlinks):
					#check to see if the user specified scraping specifically on the target host
					if (args.samesite):
						#check to see if we need to check for the .netloc attribute of a parsed absolute url
						if ("http://" in link or "https://" in link):
							#parse the absolute url
							parsed_uri = urlparse(link)
							#check to see if the host for the target url and the parsed link are the same (on the same site)
							if (parsed_uri.netloc == parsed_target.netloc):
								#add the link to the list if it belongs to the same site
								links.append(link)
						else: #append the link since it is a relative link
							links.append(link)
					else:
						links.append(link)

		#remove duplicates from the list of links
		links = list(dict.fromkeys(links))

		#loop through the links with the index and link string
		for index, link in enumerate(links):
			#check to see if this is an absolute url
			if ("https://" in link or "http://" in link):
				#get the contents of this link and add the contents of this link to the list
				print("DEPTH LEVEL: [" + str((args.depth - depth) + 1) + "] --> Scraping:", link, "-->", index)

				#get the contents of the web page
				contents = get_contents(link)
				contentlist.append(scrape_vectors(contents, depth-1, links))
			elif (link[0] == "/"): #if this is a relative url
				#get the absolute url
				absurl = hostname + link
				print("Scraping:", absurl, "-->", index)

				#retrieve the contents of the page
				contents = get_contents(absurl)
				contentlist.append(scrape_vectors(contents, depth-1, links))
		#tell the user we have finished scraping and return the list
		print("FINISHED...")
		return [links, contentlist]
	elif (depth <= 1 and args.depth > 1): #check to see if this is returning to a recursive function because of the scraping depth of more than 1
		#return the list of tags
		return vector_tags
	elif (depth <= 1 and args.depth == 1): #check to see if the scraping depth is 1, thus returning a 2d list with the target hostname and the vector tags
		#return the list of tags along with the link for a uniform format/return structure
		print("RETURNING THIS")
		return [[hostname], [vector_tags]]

#the main method
def main():
	#set a global variable for command line arguments
	global args
	args = get_args()

	#store the parsed target url
	global parsed_target
	parsed_target = urlparse(args.target)

	#store the hostname string
	global hostname
	hostname = '{uri.scheme}://{uri.netloc}'.format(uri=parsed_target)

	print("\n\n\nScraping:", hostname + "\n\n\n")

	#get the response from the original target url
	response = get_contents(args.target)

	#get the "vectors" specified in the arguments and pass the scraping depth
	#to scrape more urls if needed
	vectors = scrape_vectors(response, args.depth)

	#open a file to store the data on the tags that were scraped from the site
	data = open("data.txt", "w")

	#write the contents of the data to the respective files, and check to see if the results
	#of the web crawl are a 2d list of elements or a 1d list of elements
	if (type(vectors) is list):
		#loop through the list of tags (index 0 is the links and index 1 is the tags)
		for index, vectorlist in enumerate(vectors[1]):
			#write the url that this set of tags was scraped from (matches the index)
			data.write("*"*50 + "\n")
			data.write("URL: " + vectors[0][index] + "\n")
			data.write("*"*50 + "\n")
			#loop through the tags or "attack vectors"
			for vector in vectorlist:
				#write the tag type/name
				data.write("-"*30 + "\n")
				data.write("Tag Type: " + str(vector.name) + "\n")
				print(dir(vector))
				#list the attributes of the tag
				for attr in vector.attrs:
					data.write("\t" + attr + " : " + vector.attrs[attr] + "\n")
				#print the contents of the tag and make sure that the contents are not empty
				if (vector.contents is not None and vector.contents != []):
					data.write("[BEGIN CONTENT]\n")
					data.write(vector.prettify())
					data.write("[END CONTENT]\n")
				#write newline for clear separation
				data.write("\n")
			#write multiple newlines to separate different data sets from different urls
			data.write("*"*50 + "\n\n\n")
		print("Wrote data to:", data.name)
	elif (len(vectors) == 0):
		print("No data to write. Exiting now...")

#execute the main function
if __name__ == "__main__":
	main()
