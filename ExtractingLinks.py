def extract_links_main(url):  
    import requests
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin

    def normalize_url(href: str, base_url: str) -> str:
        """Convert relative URLs to absolute ones using the base URL."""
        return urljoin(base_url, href)

    def extract_links(html: str, base_url: str):
        """Extract and normalize all valid links from HTML content."""
        soup = BeautifulSoup(html, "html.parser")
        urls = set()

        # Extract <a href="..."> links
        for a in soup.find_all("a", href=True):
            href = a["href"]

            # Skip unwanted types
            if href.startswith(("mailto:", "tel:", "javascript:")):
                continue

            urls.add(normalize_url(href, base_url))

        # Handle <meta http-equiv="refresh" ...> redirects
        meta = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"})
        if meta and meta.get("content"):
            parts = meta["content"].split(";")
            if len(parts) > 1 and "url=" in parts[1].lower():
                url_part = parts[1].split("=", 1)[1].strip().strip('"').strip("'")
                urls.add(normalize_url(url_part, base_url))

        return sorted(urls)

    # ------------------------------
    # MAIN PROGRAM
    # ------------------------------
  

    try:
        # Download the HTML from the given URL
        response = requests.get(url)
        response.raise_for_status()  # check for errors (e.g. 404)

        html_content = response.text  # the full HTML source

        # Extract links from the page
        found_links = extract_links(html_content, url)
        from VirusTotalUrlChecker import virus_total
        count=0


        print("\n✅ Found links:")
        for link in found_links:
            if "https://" in link:
                link=link[8:]
            else:
                link=link[7:] 
            redirect_info = virus_total(link)
            if redirect_info['stats']['malicious'] > 0:
                count+=1
        if count>0:
            print(f"\nTotal Malicious Links Found: {count}")    
        else:
            print("\nNo Malicious Links Found.")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching page: {e}")

url= input("Enter a website URL: ")   
extract_links_main(url)