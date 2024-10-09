from datetime import date, datetime

# class: problem, gi_status, admission

# Problem class
class Problem():
    def __init__(self, problem_id, title, description, active: bool, start: date, end: date, link) -> None:        
        self.problem_id = problem_id
        self.title = title
        self.description = description
        self.active = active
        self.start = start
        self.end = end
        self.link = link

    @classmethod
    def make_from_dict(cls, dict):
        return cls(dict['problem_id'], dict['title'], dict['description'], dict['active'], dict['start'], dict['end'], dict['link'])
    
    def dict(self):
        return {
            'problem_id': self.problem_id,
            'title': self.title,
            'description': self.description,
            'active': self.active,
            'start': self.start,
            'end': self.end,
            'link': self.link
        }
    
    def get_id(self):
        return self.id
    
# GI status class
class gi_status():
    def __init__(self, image, description, diet, defecation) -> None:
        self.image = image
        self.description = description
        self.diet = diet
        self.defecation = defecation
    
    @classmethod
    def make_from_dict(cls, dict):
        return cls(dict['image'], dict['description'], dict['diet'], dict['defecation'])
    
    def dict(self):
        return {
            'image': self.image,
            'description': self.description,
            'diet': self.diet,
            'defecation': self.defecation
        }

# admission class
class admission():
    def __init__(self, start: date, end: date, reason, next: dict[str, date]) -> None:
        self.start = start
        self.end = end
        self.reason = reason
        self.next = next

# TPN class
class TPN():
    def __init__(self, item, volume, start, end, additive, frequency, note) -> None:
        self.item = item
        self.volume = volume
        self.start = start
        self.end = end
        self.additive = additive
        self.frequency = frequency
        self.note = note
    
    @classmethod
    def make_from_dict(cls, dict):
        return cls(dict['item'], dict['volume'], dict['start'], dict['end'], dict['additive'], dict['frequency'], dict['note'])
    
    def dict(self):
        return {
            'item': self.item,
            'start': self.start,
            'end': self.end,
            'additive': self.additive,
            'frequency': self.frequency,
            'notes': self.note
        }
    
    def get_infusion_time(self):
        start = datetime.strptime(self.start, '%H:%M')
        end = datetime.strptime(self.end, '%H:%M')
        return (end - start).hours
    
    def get_infusion_rate(self):
        return self.volume / self.get_infusion_time()