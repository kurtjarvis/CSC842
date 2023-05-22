#!/usr/bin/env python3
# 
# Author: Kurt Jarvis
# Created: 21 May 2023
# Class: CSC-842
# Purpose: A website extractor that allows us to take an html file and pull out all of the links to see if we want to investigate.

# import block
import argparse
import re
import requests
from bs4 import BeautifulSoup

# argument Parser
def parseArguments(valid_choices):
    # Set up the arguments
    parser = argparse.ArgumentParser(description="webpage extractor")
    parser.add_argument('-e', '--extractFrom', help="html file to extract",
                        nargs='+')
    parser.add_argument('-f', '--fromFile', help="use a file to extract urls")
    parser.add_argument('-s', '--selection', choices=valid_choices, 
                        default='all', help="type of embedded files to find")
    parser.add_argument("-o", "--outfile", dest='outfile',
                        help="file to save the output")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="print processing messages")
    parser.add_argument("-d", "--domains", default=False, action="store_true", help="find subdomains from the extractions")
    parser.add_argument("-D", "--domainsOnly", default=False, action="store_true", help="find subdomains from the extractions but don't show extractions")
    return parser.parse_args()

# Class to do the processing
class WebpageExtractor:
    def __init__(self, verbose):
        self.verbose = verbose
    # Give a set of HTML tags we want to extract, parse the document tree to find each one. Since href's are special, it takes 
    # a little extra step to grab it.
    def extractTags(self, source, label):
        soup = BeautifulSoup(source, "lxml")
        answer = []
        if label == 'href':
            anchors = soup.find_all("a")
            answer = [anchor.get(label) for anchor in anchors]
        elif label == 'src':
            #src is embedded inside of script like href is for a
            anchors = soup.find_all("script")
            # Since there can be inline scripts, we need to ignore those that are not referencing a file
            answer = [anchor.get(label) for anchor in anchors if anchor.get(label) is not None]
        else:
            tags = soup.find_all(label)
            for tag in tags:
                if tag.string is None:
                    answer.append(tag)
                elif tag.string.find("function("):
                    self.printMessage("Removed an anonymous function")
                else:
                    answer.append(tag.string)
        return answer
    # Give a list of results from the extractTags call, pull out the absolute references to find the subdomains available
    def findDomains(self, strings):
        cleaned_list = [url.lstrip("http://") for url in strings if url.startswith("http://")]
        cleaned_list += [url.lstrip("https://") for url in strings if url.startswith("https://")]
        answer = [item.split('/')[0] for item in cleaned_list]
        # now that we only have the absolute urls, 
        return set(answer)
    # a technique to get rid of printing helpful messages when running
    def printMessage(self, message):
        if self.verbose:
            print(message)

# helper function to isolate problems
def runoptions(options, we, valid_choices, text):
    answers = []
    if options.selection == "all":
        for option in valid_choices:
            if option == "all":
                continue
            answers += we.extractTags(text, option)
    else:
        answers += we.extractTags(text, options.selection)
    return answers

#python def for main
def main():
    # these are the choices available and it is based on html tags
    valid_choices = ["all", "src", "href", "css"]
    options = parseArguments(valid_choices)
    we = WebpageExtractor(options.verbose)
    answers = []
    text = ""
    if options.extractFrom is not None:
        for item in options.extractFrom:
            we.printMessage("Processing " + item)
            if item.startswith("http"):
                req = requests.get(item)
            else:   
                req = requests.get("https://" + item)
            if req.status_code != 200:
                print("Error:", req.status_code)
            else: 
                #text += req.text
                answers += runoptions(options, we, valid_choices, req.text)
    if options.fromFile is not None:
        try:
            for item in options.fromFile:
                we.printMessage("Processing " + item)
                with open(options.fromFile, "r") as file:
                    #text += file.read()
                    answers += runoptions(options, we, valid_choices, file.read())
        except:
            print("Error: Unable to read provided file, skipping...")

    if options.domains:
        # extract from the list to make it print per line for future grepping
        [print(item) for item in we.findDomains(answers)]
    if answers and not options.domainsOnly:
        if answers:
            for value in answers:
                print(value)
        else:
            print("No results found based on queries")

# Main instanciation
if __name__ == "__main__":
   main()
