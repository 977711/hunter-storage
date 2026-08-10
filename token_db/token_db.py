import motor.motor_asyncio
from cryptograph import NAME, DATA

class Database:
    def __init__(self, uri, database_name):
        self._client = motor.motor_asyncio.AsyncIOMotorClient(uri)
        self.db = self._client[database_name]
        self.col = self.db.access_token
        self.col2 = self.db.short_url

    async def update_premium_user_time(self, user_id, token_number, time):
        await self.col.update_one(
            {"_id": user_id},
            {"$set": {f"prm_time{token_number}": time}},
            upsert=True,
        )
        
    async def get_premium_user_time(self, user_id, token_number):
        user_data = await self.col.find_one({"_id": user_id})
        if user_data:
            return user_data.get(f"prm_time{token_number}")
        return None
        
    async def get_token_expire_date(self, user_id, token_number):
        user_data = await self.col.find_one({'_id': user_id})
        if user_data:
            return user_data.get(f'date{token_number}')
  
    async def get_total(self):
        total = await self.col2.find_one({'_id': 1234})        
        if total:
            total = total.get("total")
            return total
        return 4
        
    async def get_token_time(self):
        token_timeout = await self.col2.find_one({'_id': 1234})        
        if token_timeout:
            time = token_timeout.get(f"token_timeout")
            if time:
                return int(time)
            return int(18000)

    async def get_verify(self, id):
        user = await self.col.find_one({'_id': int(id)})
        if user:
            return user.get('verify')
        return 'all'

    async def set_verify(self, id, verify):
        await self.col.update_one({'_id': id}, {'$set': {'verify': verify}})
        
token_db = Database(DATA, NAME)
