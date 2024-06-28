import requests as rq

url = "http://127.0.0.1:5000/api"
# response = rq.post(url, json={'heading': 'Aticle',
#                                     'description': 'descriptions',
#                                     'user_id': 1})
#
# print(response.status_code)
# print(response.text)

#
# response = rq.get('http://127.0.0.1:5000/api/1')
#
# print(response.status_code)
# print(response.text)

#
#
# response = rq.patch('http://127.0.0.1:5000/api/1',
#                     json={'heading': 'Aticle',
#                            'description': 'descriptions',
#                             'user_id': 1
#                             })
#
# print(response.status_code)
# print(response.text)



response = rq.delete("http://127.0.0.1:5000/api/1")

print(response.status_code)
print(response.text)









# response = rq.post(
#     "http://127.0.0.1:5000/user",
#     json={
#         'name': 'user_6',
#         "password": "12fdesggege34"
#     },
#
# )
# print(response.status_code)
# print(response.text)
#
# response = rq.get(
#     "http://127.0.0.1:5000/user/5",
#
#
# )
# print(response.status_code)
# print(response.text)

# response = rq.patch(
#     "http://127.0.0.1:5000/user/5",
#     json={
#         'name': 'new_user',
#         "password": "1234"
#     },
#
# )
# print(response.status_code)
# print(response.text)


# response = rq.delete(
#     "http://127.0.0.1:5000/user/5",
#
#
# )
# print(response.status_code)
# print(response.text)

# response = rq.get(
#     "http://127.0.0.1:5000/user/5",
#
#
# )
# print(response.status_code)
# print(response.text)
