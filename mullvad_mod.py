#!/bin/env python3

# Dependencies
import os
import re
import sys
import glob
import json
import time
import subprocess
import argparse

# If previous data exists, reuse it
recycle_JSON = True

tmp_cache = '/tmp'

# Where mullvad is installed
binary = subprocess.run(['which', 'mullvad'], capture_output=True, text=True)

if binary.returncode != 0:
    print('Mullvad not found on this system!', file=sys.stderr)
    sys.exit(1)
else:
    binary = binary.stdout.strip()

# Cache location of generated data
pwd = os.path.dirname(os.path.realpath(__file__))
cache = f'{pwd}/.cache'
mullvad_json_output = f'{cache}/vpn_locations.json'

if not os.path.isdir(cache):
    os.mkdir(cache)

def check_previous_data(cached_data, data):

    res = {'update': True, 'cache': cached_data }

    path = cached_data.split('/')[1]
    file = cached_data.split('/')[-1]
    head_file = file.split('_')[0]
    timestamp = file.split('_')[1]
    tail_file = file.split('_')[2].split('.')[0]
    ext_file = file.split('.')[-1]

    pattern = f'/{path}/{head_file}_*_{tail_file}.{ext_file}'
    cached_files = glob.glob(f'/{path}/{head_file}_*_{tail_file}.{ext_file}')

    if len(cached_files) > 0:
        # The location of outputs are cached
        try:
            dat_list = f'{cache}/tmp.lst'
            with open(dat_list, 'w') as dat:
                dump = ('\n').join(cached_files)+'\n'
                if cached_data not in cached_files:
                    # Warning : what's in dat_list doesn't mean also in temp directory !
                    dump = dump + cached_data + '\n'
                dat.write(dump)
        except:
            print(f'Could not keep trace of cache in {dat_list}', file=sys.stderr)

        # Sorted by number, greater at the end so list has to been reversed
        last_file = sorted(cached_files, reverse=True)[0]
        try:
            with open(last_file, 'r') as f:
                prev_dat = f.readlines()
        except:
            print(f"Can't open {file}")

        prev_dat = ('').join(prev_dat).strip()

        if prev_dat == data:
            res = last_file
            res = {'update': False, 'cache': last_file }
        
    else:
        try:
            dat_list = f'{cache}/tmp.lst'
            with open(dat_list, 'w') as dat:
                dat.write(f'{cached_data}\n')
        except:
            print(f'Could not keep trace of cache in {dat_list}', file=sys.stderr)

    return res

# This function simply gets mullvad endpoints lists and store them on disk
def get_mullvad_loc():

    timestamp = int(time.time())

    # Temporary datadir is used
    cached_data = f'{tmp_cache}/proxyfier_{timestamp}_loc.dat'

    # "Rad" countains start of command
    rad = [binary, 'relay']
    # First, database is updated
    update_data = subprocess.call(rad+["update"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    # Mullvad data location, defined by indentation
    location_data_proc = subprocess.run(rad+["list"], capture_output=True, text=True)

    # Check if everything happens correctly
    if location_data_proc.returncode != 0:
        print('Mullvad not found on this system!', file=sys.stderr)
        sys.exit(1)
    else:
        location_data = location_data_proc.stdout.strip()

    # Writing of this output on disk in "cached data"
    try:
        check_location_data = check_previous_data(cached_data, location_data)
        if check_location_data['update']:
            with open(cached_data, 'w') as c:
                c.write(location_data)
        else:
            cached_data = check_location_data['cache']
    except:
        print('Error trying to cache data. Aborting...', file=sys.stderr)
        sys.exit(1)

    res = cached_data
    
    return res

# This function converts previous captured data into JSON
def transform_mullvad_loc(mullvad_data):

    if mullvad_data is None:
        print('No mullvad data', file=sys.stderr)
        sys.exit(1)
    else:

        country_list = {'countries': []}

        # Look for line starting with alnum
        start_reg = re.compile('^\w')

        try:
            with open(mullvad_data, 'r') as dat:
                loc_list = dat.readlines()
        except:
            print('Error trying to read cached data. Aborting...', file=sys.stderr)
            sys.exit(1)

        for line in loc_list:

            line_length = len(line)
            
            # If this match, current line is a country
            if start_reg.match(line):
                country_dat = line.split(' ')
                country_name = country_dat[0]
                country_code = country_dat[1][1:-2]
                entry_country = {
                    'name': country_name,
                    'code': country_code,
                    'cities': []
                }
                # Append data to the list
                country_list['countries'].append(entry_country)
                # Index data location
                country_index = len(country_list['countries']) - 1

            # If this does not start with alnum and line length is superior than 5, get data inside
            elif line_length > 5:
                leading_spaces = len(line) - len(line.lstrip())
                striped_line = line.strip()
                try:
                    # Index city location
                    cityindex = len(country_list['countries'][country_index]['cities']) - 1
                except:
                    print(f"error on line {line.strip()}. index {country_index}")
                    sys.exit(1)

                # If this condition is matched, line contain city informations
                if leading_spaces == 1 and line_length >= 5:
                    city_dat_1 = striped_line.split('(')
                    city_dat_2 = city_dat_1[1].split(')')
                    city_code = city_dat_2[0]
                    try:
                        city_name = city_dat_1[0].strip().split(',')[0].strip()
                        city_region = city_dat_1[0].strip().split(',')[1].strip()
                        entry_city = {
                            'name': city_name,
                            'region': city_region,
                            'code': city_code,
                            'servers': []
                        }
                    except:
                        city_name = city_dat_1[0].strip()
                        entry_city = {
                            'name': city_name,
                            'code': city_code,
                            'servers': []
                        }
                    country_list['countries'][country_index]['cities'].append(entry_city)
                # Else, line is about vpn servers
                else:
                    server_dat_1 = striped_line.split('(')
                    server_name = server_dat_1[0].strip()
                    server_dat_2 = server_dat_1[1].split(')')
                    server_dat_3 = server_dat_2[1].split(' - ')
                    server_info = server_dat_3[1].strip()
                    try:
                        server_ipv4 = server_dat_2[0].split(',')[0].strip()
                        server_ipv6 = server_dat_2[0].split(',')[1].strip()
                        entry_server = {
                            'name': server_name,
                            'ipv4': server_ipv4,
                            'ipv6': server_ipv6,
                            'infos': server_info
                        }
                    except:
                        server_ipv4 = server_dat_2[0].strip()
                        entry_server = {
                            'name': server_name,
                            'ipv4': server_ipv4,
                            'infos': server_info
                        }
                    country_list['countries'][country_index]['cities'][cityindex]['servers'].append(entry_server)

        # Try to write JSON to disk
        try:
            with open(mullvad_json_output, 'w') as loc:
                json.dump(country_list, loc, indent=4)
        except:
            print('Error writing data in JSON file', file=sys.stderr)

        mullvad_content = json.dumps(country_list)
        return country_list
    

# Write data somewhere in tmp files
mullvad_data = get_mullvad_loc()

# Convert this data to JSON for easy manipulation
mullvad_content = 'Mullvad data is empty !'

# Recycle former JSON data if exists
if recycle_JSON and os.path.isfile(mullvad_json_output):
    try:
        with open(mullvad_json_output, 'r') as jdat:
            mullvad_content = json.load(jdat)
    except:
        print('Error trying to use former JSON data file', file=sys.stderr)
        mullvad_content = transform_mullvad_loc(mullvad_data)
else:
    mullvad_content = transform_mullvad_loc(mullvad_data)

def exists_country(country):
    if not country:
        return json.dumps({'answer': {'exists': False}})
    res = {'answer': {'country': country, 'exists': False}}
    for sample_country in mullvad_content['countries']:
        if sample_country['name'].lower() == country.lower() or sample_country['code'].lower() == country.lower():
            res['answer']['country'] = sample_country['name']
            res['answer']['exists'] = True
            res['answer']['code'] = sample_country['code']
            res['answer']['cities'] = sample_country['cities']
    if res['answer']['exists'] == False:
        print(f'Country {country} not found', file=sys.stderr)
    return json.dumps(res)

def exists_city(city):
    #match = []
    if not city:
        return json.dumps({'answer': {'exists': False}})
    res = {'answer': {'city': city, 'exists': False}}
    for sample_country in mullvad_content['countries']:
        country_name = sample_country['name']
        for sample_city in sample_country['cities']:
            if sample_city['name'].lower() == city.lower() or sample_city['code'].lower() == city.lower():
                #match.append(sample_city)
                res['answer']['city'] = sample_city['name']
                res['answer']['country'] = sample_country['name']
                res['answer']['exists'] = True
                res['answer']['code'] = sample_city['code']
                res['answer']['servers'] = sample_city['servers']
    if res['answer']['exists'] == False:
        print(f'City {city} not found', file=sys.stderr)
    return json.dumps(res)

def exists_server(server):
    #match = []
    if not server:
        return json.dumps({'answer': {'exists': False}})
    res = {'answer':{'server': server, 'exists': False}}
    for sample_country in mullvad_content['countries']:
        country_name = sample_country['name']
        for sample_city in sample_country['cities']:
            city_name = sample_city['name']
            for sample_server in sample_city['servers']:
                if sample_server['name'].lower() == server.lower():
                    #match.append(sample_city)
                    res['answer']['country'] = country_name
                    res['answer']['city'] = city_name
                    res['answer']['exists'] = True
                    res['answer']['ip'] = sample_server['ipv4']
                    try:
                        res['answer']['ip'] = f"{res['answer']['ip']}, {sample_server['ipv6']}"
                    except:
                        pass
    if res['answer']['exists'] == False:
        print(f'Server {server} not found', file=sys.stderr)
    return json.dumps(res)

def set_mullvad_loc(country=None, city=None, server=None, enable=True):
    rad = [binary, 'relay', 'set', 'location']
    location = []

    dat_vpn = json.loads(exists_server(server)) 
    dat_place = json.loads(exists_city(city))
    dat_state = json.loads(exists_country(country))

    if dat_vpn['answer']['exists']:
        vpn = dat_vpn['answer']['server']
        location.append(vpn)
    if dat_place['answer']['exists']:
        place = dat_place['answer']['code']
        location.append(place)
    if dat_state['answer']['exists']:
        state = dat_state['answer']['code']
        location.append(state)

    location.reverse()

    cmd_set = rad+location
    cmd_set_output = (' ').join(cmd_set)

    set_loc_proc = subprocess.run(cmd_set, capture_output=True, text=True)
    set_loc_output = f"{set_loc_proc.stdout}\n{set_loc_proc.stderr}"
    print(f"\n{cmd_set_output}\n{set_loc_output}", file=sys.stderr)

    if enable:

        cmd_en = [binary, "connect"]
        cmd_en_output = (' ').join(cmd_en)
        en_loc_proc = subprocess.run(cmd_en, capture_output=True, text=True)
        en_loc_output = f"{set_loc_proc.stdout}\n{set_loc_proc.stderr}"
        print(f"\n{cmd_en_output}\n{en_loc_output}", file=sys.stderr)

def updater(get, state, place, vpn):

    res = None

    if get:

        data_0 = {'answer': {'exists': False}}
        data_1 = {'answer': {'exists': False}}
        data_2 = {'answer': {'exists': False}}
        data = data_0

        errors = []

        if vpn:
            data_1 = json.loads(exists_server(vpn))
            if not data_1['answer']['exists']:
                errors.append(f"server '{vpn}' not found")
            else:
                data = data_1

        if place:
            data_2 = json.loads(exists_city(place))
            if not data['answer']['exists']:
                if not data_2['answer']['exists']:
                    errors.append(f"city '{place}' not found")
                else:
                    if data['answer']['exists'] and data['answer']['city'] != data_2['answer']['city']:
                        errors.append("city does not match with chosen server")
                    elif len(errors) <= 0:
                        data = data_2

        if state:
            data_3 = json.loads(exists_country(state))
            if not data['answer']['exists']:
                if not data_3['answer']['exists']:
                    errors.append(f"country '{state}' not found")
                else:
                    if data_1['answer']['exists'] and data_1['answer']['country'] != data_3['answer']['country']:
                        errors.append("country does not match with chosen server")
                    if data_2['answer']['exists'] and data_2['answer']['country'] != data_3['answer']['country']:
                        errors.append("country does not match with chosen location")
                    elif len(errors) <= 0:
                        data = data_3

        if len(errors) >= 1:
            data['errors'] = errors

        res = json.dumps(data)

    elif state or place or vpn:
        set_mullvad_loc(state, place, vpn)
        res = json.dumps({'status': '200 OK'})

    return res


def main():

    script_name = os.path.basename(__file__)

    parser = argparse.ArgumentParser(prog=script_name, description='Python overlay implementation for Mullvad client')
    parser.add_argument('-g', '--get', action=argparse.BooleanOptionalAction)
    parser.add_argument('-s', '--state')
    parser.add_argument('-p', '--place')
    parser.add_argument('-v', '--vpn')

    args = parser.parse_args()

    state = args.state
    place = args.place
    vpn = args.vpn

    get = args.get

    launched = updater(get, state, place, vpn)
    if not launched:
        parser.print_help()
    else:
        print(launched)

if __name__ == '__main__':
    main()