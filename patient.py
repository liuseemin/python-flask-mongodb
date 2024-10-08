from patient_data import Problem, gi_status
from bson.objectid import ObjectId

# patient class
class Patient():
    def __init__(self, id, name, age: int, sex, problems: list[ObjectId], OP_hx, GI_status: gi_status, lab: dict, notes, admission_hx) -> None:
        self.id = id
        self.name = name
        self.age = age
        self.sex = sex
        self.problems = problems
        self.OP_hx = OP_hx
        self.GI_status = GI_status
        self.lab = lab
        self.notes = notes
        self.admission_hx = admission_hx
    
    @classmethod
    def make_from_dict(cls, dict):
        return cls(dict['id'], dict['name'], dict['age'], dict['sex'], dict['problems'], dict['OP_hx'], dict['GI_status'], dict['lab'], dict['notes'], dict['admission_hx'])
    
    def dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'age': self.age,
            'sex': self.sex,
            'probmels': self.problems,
            'OP_hx': self.OP_hx,
            'GI_status': self.GI_status,
            'lab': self.lab,
            'notes': self.notes,
            'admission_hx': self.admission_hx
        }
    
    def get_id(self):
        return self.id