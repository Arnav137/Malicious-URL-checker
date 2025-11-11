def virus_total(url):
    # vt_url_check.py
    import time
    import requests

    VT_POST = "https://www.virustotal.com/api/v3/urls"
    VT_ANALYSES = "https://www.virustotal.com/api/v3/analyses/{}"
    with open("C:\\Engineering\\ApiKey.txt","r") as f:
        API_KEY=f.read().strip()         
    HEADERS = {"x-apikey": API_KEY} if API_KEY else {}

    def submit_url(url):
        """Submit URL to VT. Returns analysis id or raises."""
        resp = requests.post(VT_POST,data={"url":url}, headers=HEADERS, timeout=30)
        if resp.status_code == 200 or resp.status_code == 201:
            return resp.json()["data"]["id"]
        elif resp.status_code == 204:
            raise RuntimeError("Rate limit reached (204). Slow down.")
        else:
            raise RuntimeError(f"Submit failed: {resp.status_code} {resp.text}")

    def poll_analysis(analysis_id, wait_seconds=5, max_wait=60):
        """Poll analysis endpoint until 'status' is 'completed' or timeout."""
        elapsed = 0
        while elapsed < max_wait:
            resp = requests.get(VT_ANALYSES.format(analysis_id), headers=HEADERS, timeout=30)
            if resp.status_code == 200:
                j = resp.json()
                status = j.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    return j
                # still running -> wait
            elif resp.status_code == 204:
                raise RuntimeError("Rate limit reached while polling.")
            else:
                raise RuntimeError(f"Analysis fetch error: {resp.status_code} {resp.text}")

            time.sleep(wait_seconds)
            elapsed += wait_seconds

        raise TimeoutError("Timed out waiting for analysis completion")

    def parse_report(json_obj):
        """Return summarized info: malicious counts, per-engine verdict sample, permalink."""
        attrs = json_obj.get("data", {}).get("attributes", {})
        stats = attrs.get("stats") or attrs.get("last_analysis_stats")  # different responses vary
        results = attrs.get("results") or attrs.get("last_analysis_results")
        permalink = json_obj.get("meta", {}).get("url") or None

        summary = {"stats": stats, "engines_sample": {}, "permalink": permalink}

        # take up to 5 engines as sample
        if isinstance(results, dict):
            count = 0
            for engine, info in results.items():
                summary["engines_sample"][engine] = {
                    "category": info.get("category"),
                    "result": info.get("result"),
                    "engine_version": info.get("engine_version"),
                }
                count += 1
                if count >= 10:
                    break

        return summary

    def check_url(url):
        aid = submit_url(url)
        analy = poll_analysis(aid, wait_seconds=10, max_wait=120)
        return parse_report(analy)
    return check_url(url)
    

