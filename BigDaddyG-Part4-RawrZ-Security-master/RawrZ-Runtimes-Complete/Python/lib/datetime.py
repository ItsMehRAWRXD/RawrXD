"""RawrZ Python datetime module"""
class datetime:
    def __init__(self, year, month, day):
        self.year = year
        self.month = month
        self.day = day
    
    @staticmethod
    def now():
        return datetime(2025, 1, 1)
