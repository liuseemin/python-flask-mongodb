from datetime import date

# class: probme, gi_status, admission

# Problem class
class problem():
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
    
class admission():
    def __init__(self, start: date, end: date, reason, next: dict[str, date]) -> None:
        self.start = start
        self.end = end
        self.reason = reason
        self.next = next
