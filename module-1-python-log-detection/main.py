# define a function that can open and read all files
def read_log_file(file_path):
    with open(file_path, "r") as file:
        lines = file.readlines()
    return lines


# define a function that parses the login attempts to show either a failed or successful login attempt by users
def parse_log_line(line):

    parts = line.split()

    # ignore lines that are not login attempts
    if "Failed password" not in line and "Accepted password" not in line:
        return None

    # classify failed SSH authentication events
    # create variables for both username and ip_address from the log event
    if "Failed password" in line:
        event_type = "failed"
        username = parts[8]
        ip_address = parts[10]

    # classify successful SSH authentication events
    # create variables for both username and ip_address from the log event
    elif "Accepted password" in line:
        event_type = "accepted"
        username = parts[8]
        ip_address = parts[10]

    # return the three variables from the function
    return event_type, username, ip_address


# define a function that aggregates failed login attempts to specific IP addresses
def detect_failed_logins(events):

    failed_attempts = {}

    # create a for loop to go through each line of the file
    for event in events:

        # safeguard against runtime errors if event is None
        if event is None:
            continue

        # extract event type and source IP from parsed event tuple
        event_type = event[0]
        ip_address = event[2]

        # using conditions to count number of failed login attempts for later detection
        if event_type == "failed":

            if ip_address not in failed_attempts:
                failed_attempts[ip_address] = 1

            else:
                failed_attempts[ip_address] += 1

    return failed_attempts
     
# define a function that classifies IPs by failed login count
def classify_severity(failed_attempts):

    alerts = []

    for ip, count in failed_attempts.items():
        
      # classify high-severity brute-force threshold
      if count >= 5: 
            severity = "HIGH"

      # classify medium-severity threshold
      elif count >= 3:
            severity = "MEDIUM"

      else:
          continue
        
      alerts.append((ip, count, severity))
      
    return alerts

# main execution pipeline that runs the entire detection workflow
def main():

    # specify the log file that will be analyzed
    log_file = "sample_auth.log"

    # read the contents of the log file and store each line in a list
    lines = read_log_file(log_file)

    # create an empty list to store parsed authentication events
    parsed_events = []

    # loop through each line from the log file
    for line in lines:

        # send the line to the parser function to extract event data
        event = parse_log_line(line)

        # add the parsed event (or None if irrelevant) to the list
        parsed_events.append(event)

    # aggregate failed login attempts by IP address
    failed_attempts = detect_failed_logins(parsed_events)

    # classify IP addresses into severity levels based on thresholds
    alerts = classify_severity(failed_attempts)

    # iterate through the alert list and display the results
    for alert in alerts:
        print(alert)

    # import the csv module so we can write detection results to a file
    import csv

    # open the output file in write mode
    # newline="" prevents blank lines being inserted on some systems
    with open("output/detections.csv", "w", newline="") as file:

        # create a CSV writer object
        writer = csv.writer(file)

        # write the header row so the output is readable
        writer.writerow(["IP Address", "Failed Attempts", "Severity"])

        # loop through each alert tuple and write it to the CSV file
        for alert in alerts:

            # write each alert record to the CSV file
            writer.writerow(alert)
            
# this ensures the script only runs when executed directly,
# not when imported as a module in another Python file
if __name__ == "__main__":
    main()
