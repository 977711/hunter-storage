import aiohttp
from g4f.client import Client
from re import compile, search, IGNORECASE
from anitopy import parse


episode_keys = ["episode", "Episode", "EPISODE"]   
quality_keys = ["quality", "Quality", "QUALITY"]
season_keys = ["season", "Season", "SEASON"]

pattern1 = compile(r'S(\d+)(?:E|EP)(\d+)')
pattern2 = compile(r'S(\d+)\s*(?:E|EP|-\s*EP)(\d+)')
pattern3 = compile(r'(?:[([<{]?\s*(?:E|EP)\s*(\d+)\s*[)\]>}]?)')
pattern4 = compile(r'(?:\s*-\s*(\d+)\s*)')
pattern5 = compile(r'S(\d+)[^\d]*(\d+)', IGNORECASE) 
pattern6 = compile(r'(E|EP)(\d\.\d)')
pattern7 = compile(r'(?<!\d)(\d\.\d{1,2})(?!\d)')
pattern8 = compile(r'(\d+)')
pattern9 = compile(r'\[(\d+)\s-\s(.+?)\]')
pattern10 = compile(r'\[(\d+)\s*')
pattern11 = compile(r'episode (\d+)', IGNORECASE)


async def fetch_response(query):
    try:
        client = Client()
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": query}],
            web_search=False
        )
        return response.choices[0].message.content
    except:
        return None


async def extract_quality(filename, ai=False):
    if ai:
        ask = f""" 
Extract only the resolution like 1080p, 720p, 480p.etc from the following filename:
'{filename}'

Return only the resolution, without any additional text or explanation.
"""
        ans = await fetch_response(ask)
        try:
            if ans.endswith('p'):
                return ans
            else:
                return await extract_quality(filename, ai=False)
        except Exception as e:
            return await extract_quality(filename, ai=False)
    else:
        quality = ""    
        pattern = compile(r'\b(?:.*?(\d{3,4}[^\dp]*p).*?|.*?(\d{3,4}p))\b', IGNORECASE)
        if match := search(pattern, filename):     
            quality = match.group(1) or match.group(2)
        return quality


async def extract_episode(filename, ai=False):  
    if ai:
        ask = f""" 
Extract only the episode number from the following filename:
'{filename}'

Return only the number, without any additional text or explanation.
"""
        ans = await fetch_response(ask)
        try:
            if ans.isdigit():
                return ans
            else:
                return await extract_episode(filename, ai=False)
        except:
            return await extract_episode(filename, ai=False)
    else:
        if match := search(pattern1, filename):
            return match.group(2)  
        if match := search(pattern2, filename):
            return match.group(2)  
        if match := search(pattern3, filename):
            return match.group(1)  
        if match := search(pattern4, filename):
            return match.group(1)  
        if match := search(pattern5, filename):
            return match.group(2)  
        if match := search(pattern6, filename):
            return match.group(2)  
        if match := search(pattern7, filename):
            return match.group(1)            
        if match := search(pattern8, filename):
            return match.group(1)
        if match := search(pattern9, filename):
            return match.group(1)
        if match := search(pattern10, filename):
            return match.group(1)
        if match := search(pattern11, filename):
            return match.group(1)
        return None

    
async def extract_season(filename, ai=False):
    if ai:
        ask = f""" 
Extract only the season number from the following filename:
'{filename}'

Return only the number, without any additional text or explanation.
"""
        ans = await fetch_response(ask)
        try:
            if ans.isdigit():
                return ans
            else:
                return await extract_season(filename, ai=False)
        except:
            return await extract_season(filename, ai=False)
    else:
        string = ""
        dic = parse(filename)  
        if "anime_season" in dic.keys():
            season = str(dic["anime_season"])
            if season not in ["720", "1080"]:
                if len(season) == 1:
                    season = season.zfill(2)
                string = f"{season}"
            else:
                season = ""
        else:
            string = ""
        return string
