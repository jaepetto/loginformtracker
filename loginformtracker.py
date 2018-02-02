import pprint
import re

import requests
import urltools as urltools
from bs4 import BeautifulSoup

from checked_url import CheckedUrl
import urllib3
urllib3.disable_warnings()
from urllib.parse import urljoin

import requests_cache
requests_cache.install_cache('web_cache', expire_after=43200)

import pickle
import os.path


def normalize_url(url: str) -> str:
    temp_url = urltools.extract(url)

    # Remove the jsessionid from the path (unless you want to end up in an infinite loop...)
    new_path = re.sub(r';jsessionid=\w{32}', '', temp_url.path)

    new_url = urltools.URL(scheme=temp_url.scheme, username=temp_url.username, password=temp_url.password,
                           subdomain=temp_url.subdomain,
                           domain=temp_url.domain, tld=temp_url.tld, port=temp_url.port, path=new_path,
                           query=temp_url.query,
                           fragment='', url='')
    new_url = urltools.construct(new_url)
    return urltools.normalize(new_url)


def check_password_input_box(page_content: str) -> bool:
    soup = BeautifulSoup(page_content, "html.parser")
    password_inputs = soup.find_all(name='input', attrs={"type": "password"})
    return len(password_inputs) > 0


def get_external_links(base_url: str, page_content: str) -> list:
    return_value = []

    soup = BeautifulSoup(page_content, "html.parser")

    links = soup.find_all(name='a', attrs={"href": True})
    for link in links:
        if not str.startswith(link.get('href'), '#'):
            absolute_destination = normalize_url(urljoin(base_url, link.get('href')))
            if absolute_destination != base_url \
                    and absolute_destination not in return_value \
                    and '.epfl.ch' in str.lower(absolute_destination):
                return_value.append(absolute_destination)

    iframes = soup.find_all(name='iframe', attrs={'src': True})
    for iframe in iframes:
        absolute_source = normalize_url(urljoin(base_url, iframe.get('src')))
        if absolute_source != base_url \
                and absolute_source not in return_value \
                and '.epfl.ch' in absolute_source:
            return_value.append(normalize_url(absolute_source))

    return return_value


def check_url(url_to_check: str, content_type_patterns_to_include: list) -> CheckedUrl:
    return_value = CheckedUrl(url=url_to_check, flagged_as_unsafe=False, messages=[], external_links=[])
    try:
        req = requests.head(url=url_to_check, allow_redirects=True, timeout=2, verify=False)
        should_be_retrieved = False
        for content_type_pattern_to_include in content_type_patterns_to_include:
            if re.match(content_type_pattern_to_include, req.headers['content-type'], re.IGNORECASE):
                should_be_retrieved = True
                return_value.messages.append("INFO: the content-type is matching one the content types to be retrieved")

        if not should_be_retrieved:
            print("toto")

        if should_be_retrieved:
            req = requests.get(url=url_to_check, allow_redirects=True, timeout=2, verify=False)
            return_value.landing_url = req.url
            return_value.flagged_as_unsafe = check_password_input_box(req.content)
            return_value.external_links = get_external_links(base_url=return_value.landing_url, page_content=req.content)
    except requests.exceptions.MissingSchema:
        return_value.messages.append("ERROR: Missing schema exception")
    except requests.exceptions.ConnectionError:
        return_value.messages.append("ERROR: Connection error")
    finally:
        return return_value


def dump_data(data: object, name: str) -> None:
    with open(str('{}.pickle').format(name), 'wb') as f:
        # Pickle the 'data' dictionary using the highest protocol available.
        pickle.dump(data, f, pickle.HIGHEST_PROTOCOL)


def load_data(name: str) -> object:
    file_name = str('{}.pickle').format(name)
    if os.path.isfile(file_name):
        with open(file_name, 'rb') as f:
            # The protocol version used is detected automatically, so we do not
            # have to specify it.
            data = pickle.load(f)
            return data
    else:
        return []


def load_urls_to_check(filepath: str, exclusion_patterns: list) -> list:
    return_value = []

    # Starts by trying to load the urls passed in the parameters file
    with open(filepath) as f:
        return_value = f.readlines()
        return_value = [normalize_url(x.strip()) for x in return_value]

    # Try to load data that have been serialized
    additional_urls = load_data('urls_to_check')
    for additional_url in additional_urls:
        additional_url = normalize_url(additional_url)
        if additional_url not in return_value and not url_should_be_excluded(additional_url, exclusion_patterns):
            return_value.append(additional_url)

    return return_value


def load_checked_urls(exclusion_patterns:list) -> list:
    return_value = []

    # load already serialized data
    additional_checked_urls = load_data('checked_urls')
    for additional_checked_urls in additional_checked_urls:
        checked_url_to_add = CheckedUrl(url=normalize_url(additional_checked_urls.url),
                                                          landing_url=additional_checked_urls.landing_url,
                                                          flagged_as_unsafe=additional_checked_urls.flagged_as_unsafe,
                                                          messages=additional_checked_urls.messages,
                                                          external_links=additional_checked_urls.external_links)
        if not url_should_be_excluded(checked_url_to_add.url, exclusion_patterns):
            return_value.append(checked_url_to_add)

    return return_value


def load_exclusion_patterns(filepath: str) -> list:
    with open(filepath) as f:
        return_value = f.readlines()
        return_value = [x.strip() for x in return_value]
    return return_value


def load_content_types_to_include(filepath:str) -> list:
    with open(filepath) as f:
        content_types_to_include_patterns = f.readlines()
        content_types_to_include_patterns = [x.strip() for x in content_types_to_include_patterns]
    return content_types_to_include_patterns


def url_should_be_excluded(url: str, exclusion_patterns:list) -> bool:
    return_value = False
    for exclusion_pattern in exclusion_patterns:
        if re.match(exclusion_pattern, url, re.IGNORECASE):
            return_value = True
    return return_value


if __name__ == '__main__':

    # Load the list of url patterns to be excluded
    exclusion_patterns = load_exclusion_patterns('exclude_patterns.txt')

    # Load the list of content-types to be included
    content_types_to_include_patterns = load_content_types_to_include('content_type_patterns.txt')

    # Starting points
    urls_to_check = load_urls_to_check('urls_to_check.txt', exclusion_patterns)

    # Load the list of already checked urls
    checked_urls = load_checked_urls(exclusion_patterns)

    while len(urls_to_check) > 0:
        url_to_check = urls_to_check.pop()

        print("Checking '{}' ({} checked, {} more to go)".format(url_to_check, len(checked_urls), len(urls_to_check)))
        current_result = check_url(url_to_check, content_types_to_include_patterns)
        checked_urls.append(current_result)
        for url in current_result.external_links:

            # Checks if the url should be excluded
            should_be_excluded = url_should_be_excluded(url, exclusion_patterns)

            # Checks if the url has already been checked
            already_been_checked = False
            for checked_url in checked_urls:
                if checked_url.url == url or checked_url.landing_url == url:
                    already_been_checked = True

            # Checks if the url is already in the list of urls to be checked
            already_in_list_to_check = (url in urls_to_check)

            if not should_be_excluded and not already_been_checked and not already_in_list_to_check:
                urls_to_check.append(url)

        dump_data(checked_urls, 'checked_urls')
        dump_data(urls_to_check, 'urls_to_check')

    pp = pprint.PrettyPrinter(indent=4, compact=True)
    pp.pprint(checked_urls)

