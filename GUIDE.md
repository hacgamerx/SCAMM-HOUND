pip install phonenumbers flask
python scamhound.py phone +18005550123 --case sc_center1   # recon + OSINT links
python scamhound.py ipinfo 203.0.113.7 --case sc_center1   # geolocate a hit
python scamhound.py tracker --port 80 --case sc_center1    # run on your VPS
python scamhound.py report --case sc_center1               # compile for IC3/bank
