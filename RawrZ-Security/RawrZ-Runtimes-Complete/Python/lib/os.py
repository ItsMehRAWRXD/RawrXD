"""RawrZ Python os module"""
import sys

def getcwd():
    return "."

def listdir(path="."):
    return []

def mkdir(path):
    pass

def remove(path):
    pass

path = type('path', (), {
    'exists': lambda p: True,
    'join': lambda *args: '/'.join(args),
    'basename': lambda p: p.split('/')[-1],
    'dirname': lambda p: '/'.join(p.split('/')[:-1])
})()
