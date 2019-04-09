#!/usr/bin/env python3
# This code uses Python 3.

"""
Copyright (c) 2019 Jeffery Patton <roundduckman2@gmail.com>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""

# BTW, had to place license since I'm distributing the software, and I licensed most of this (excluding any stuff borrowed from Stack Overflow) under OpenBSD's license, since it's pretty simple and still pretty equal with the project's MIT license.
# If you don't like this, tell me and I'll flip it to MIT for consistency's sake.

# import needed modules
import requests
from bs4 import BeautifulSoup
import re
import os

REGEX_FOR_INITAL_FILE = r"""(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:\'\".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))""" # Ripped from https://stackoverflow.com/questions/520031/whats-the-cleanest-way-to-extract-urls-from-a-string-using-python, which came partly from https://daringfireball.net/2010/07/improved_regex_for_matching_urls. This is ridiculous for any beginner to understand, lol, but was what I found so I could extract all URLs from the text file.

HEADERS = {   # record user information to be sent to sites being crawled/parsed
    'User-Agent': 'Jeffery Patton, roundduckman.neocities.org',
    'From': 'roundduckman2@gmail.com'
}


patch_list = [] # initalize list used for storing the data of each patch. NOTE: This may end up making this program a bit memory intensive, considering how many patches will be downloaded. O_o


def text_analyze(url): # define text analyzing function
    cve_list = requests.get(url, headers = HEADERS) # request to get data from CVE list and save it to cve_list
    if cve_list.status_code == 200: # if connection seuccessful:
        found_pages = [] # initalize page record
        cve_soup = BeautifulSoup(cve_list.text, 'lxml') # create soup of the CVE list, as it is technically a "webpage"
        cve_lines = cve_soup.text.split('\n') # split the file into a list of individual lines of text
        for line in cve_lines: # do this for all lines in file
            if (("http://" in line) or ("https://" in line)) and ("NOTE:" in line): # search for URLs in lines with "NOTE:" in the text; I need to get patches from the notes.
                urls = re.findall(REGEX_FOR_INITAL_FILE, line) # find all urls on each note line
                if isinstance(urls, (list, tuple)) == True: # detect if the url search gives out its own table/tuple instead of being just a single url, just in case if there's two urls on a line
                    for url in urls: # add each url in the mini-list to the found_pages list
                        found_pages.append(url)
                else: # if the "urls" is just a single url, as what it normally should be:
                    found_pages.append(urls) # add them to the list of found pages
        patch_finder(found_pages) # call patch finder with the found_pages list as an argument
    else:
        print("Couldn't connect to Debian's CVE list, ending program.") # give error if you can't connect to the CVE list

def patch_finder(page_list): # define patch finder function
    global patch_list # make patch list editable in this function
    for link in page_list: # count the pages in the page list
        if "github.com" in link: # do the following for GitHub links
            if "commit" in link: # determine if the link is a commit one
                if not(link.endswith('.patch')): # determine if link needs ".patch" to download patch
                    link = link + '.patch' # add .patch for the link variable to be used in the record patch function
                patch_request = requests.get(link, headers = HEADERS) # download patch
                if patch_request.status_code == 200: # if connection successful:
                    patch_list.append(patch_request.text) # record patch to list
                else:
                    print("Failed at downloading patch at", link) # give error if downloading patch failed
            elif "issues" in link: # determine if the link is a link to an issue
                parse_for_patches("github", link) # call search_patch function to search for commit links
        elif "bugs.php.net" in link:
            parse_for_patches("bugreport/php", link)
        elif "sourceware.org/bugzilla" in link:
            parse_for_patches("bugreport/sourceware", link)
        elif "git.ganeti.org" in link :                                  # These elif's are supposed to write in a special command to the
            parse_for_patches("git/ganeti", link)                        # parse_for_patches function, which consists of "<group/source>"
        elif "git.php.net" in link :                                     # and the page to look up. Yes, this is pretty messy.
            parse_for_patches("git/php", link)
        elif "git.gnupg.org" in link :
            parse_for_patches("git/gnupg", link)
        elif "git.kernel.org" in link :
            parse_for_patches("git/linux", link)
        elif "git.libav.org" in link:
            parse_for_patches("git/libav", link)
        elif "libvirt.org/git" in link:
            parse_for_patches("git/libvirt", link)
        elif "git.openssl.org" in link:
            parse_for_patches("git/openssl", link)
        elif "git.qemu.org" in link:
            parse_for_patches("git/qemu", link)
        elif "git.samba.org" in link:
            parse_for_patches("git/samba", link)
        elif "git.videolan.org" in link:
            parse_for_patches("git/vlc", link)
        elif "code.wireshark.org" in link:
            parse_for_patches("git/wireshark", link)
        elif "sourceware.org/git/" in link:
            parse_for_patches("git/sourceware", link)
        elif link.endswith('.patch'): # if the link so happens to be a patch link:
            patch_request = requests.get(link, headers = HEADERS) # download patch
            if patch_request.status_code == 200: # if connection is successful:
                patch_list.append(patch_request.text) # record patch to list
            else:
                print("Failed at downloading patch at", link) # send error upon connection failure

def parse_for_patches(type, link): # initalize function
    global patch_list # make patch_list editable on this function
    try:  # run these when there is no missing schema error
        page = requests.get(link, headers = HEADERS)
        if page.status_code == 200: # if connection is successful:
            page_soup = BeautifulSoup(page.content, "lxml")
            if type == "github": # detect if this link is of the "github" group/source
                patch_links = [item['href'] for item in page_soup.select('.commit-link')]# Search for commit links; this came from QHarr (https://stackoverflow.com/users/6241235/qharr) who answered my question on Stack Overflow: https://stackoverflow.com/a/55555676/6158910; this part (and others using a similar fashion to find links) is licensed under cc by-sa 3.0 I think, as said on the bottom of Stack Overflow.
                if patch_links == []: # if found no link, output that it found no link
                    print("didn't find patch link in", link)
            if "bugreport" in type:  # detect if this link is of the bugreport group
                patch_links = [item['href'] for item in page_soup.select('a:contains(patch), a:contains(fix)')] # find links from <a>'s named "patch" or "fix;" this covers cases where patches are often also called "fix"
                if patch_links == []: # if found no link, output that it found no link
                    print("didn't find patch link in", link)
            if "git" in type: # detect if this link is of the git group
                patch_links = [item['href'] for item in page_soup.select('a:contains(patch)')] # find links from <a>'s named "patch"
                if patch_links == []: # if found no link, output that it found no link
                    print("didn't find patch link in", link)
            for patch in patch_links: # do this to all patches recorded on page
                if type == "github":
                    patch = patch + ".patch" # turn commit link into patch link
                elif "ganeti" in type:
                    patch = "http://git.ganeti.org" + patch
                elif type == "git/sourceware":
                    patch = "http://sourceware.org/" + patch
                elif type == "bugreport/sourceware":
                    patch = "http://sourceware.org/bugzilla/" + patch
                elif "qemu" in type:                                    # This is partly why all the elif's earlier, this is a way for a
                    patch = "http://git.qemu.org" + patch               # beginner like me to add the correct base url to each patch
                elif "samba" in type:                                   # link; most patch links are incomplete links so they need
                    patch = "http://git.samba.org" + patch              # to have the patcch link added after the base url.
                elif "vlc" in type:                                     # Basically these detect the source and/or type, and plan the
                    patch = "https://git.videolan.org" + patch          # output accordingly
                elif "wireshark" in type:
                    patch = "https://code.wireshark.org" + patch        
                elif type == "bugreport/php":                              # in the case of php's bug tracker, add "&download=1,"
                    patch = "http://bugs.php.net/" + patch + "&download=1" # to download the patch and not a patch info page
                elif type == "git/php":
                    patch = "http://git.php.net" + patch
                elif "openssl" in type:
                    patch = "http://git.openssl.org" + patch
                elif "libvirt" in type:
                    patch = "http://libvirt.org/" + patch
                elif "linux" in type:
                    patch = "http://git.kernel.org" + patch
                elif "libav" in type:
                    patch = "http://git.libav.org" + patch
                elif "gnupg" in type:
                    patch = "http://git.gnupg.org" + patch
                patch_request = requests.get(patch, headers = HEADERS) # after patch link variable is set up, use it as the url for the request
                if patch_request.status_code == 200: # if connection successful:
                    patch_list.append(patch_request.text) # save patch to patch_list variable
                else: # if there is an error:
                    print("Error downloading file at", patch) # give error
        else: # if an error occurs:
            print("couldn't successfully find patch link in", link)
    except requests.exceptions.MissingSchema: # detect this error I saw when running without this earlier; this is some invalid URL of a sort
        print("Invalid URL or missing patch at", link) # give error

def patch_writer(patches): # define writer function
    count = 0 # initalize the count used for naming files
    os.makedirs((os.path.realpath('.') + "/patches/"), exist_ok=True) # make a local "patches" folder and check if it exists already
    for patch in patches: # for each patch in the list:
        count += 1 # iterate naming counter
        patch_file = open("patches/" + str(count) + ".patch", 'w') # create buffer for an individual patch file
        patch_file.write(str(patch)) # write contents of recorded patch to the file
        patch_file.close() # save/close the file
        print("A patch was successfully written.") # tell user that the patch is written.
    print("Patches are found and written.") # give signal of completion
text_analyze("https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/CVE/list") # start program at text_analyze function; have it analyze the CVE list
patch_writer(patch_list) # save patches to drive after patches are recorded
