# NVDSearcher

Application that searches an NVD database for vulnerabilities relevant to the services you use.

There are a few different ways to use this application because we were not able to decide which direction we wanted it to be executed.
Below are the descriptions of how each usecase is preformed.

------------------------------------

Running the python script on windows

------------------------------------

1. Download the NVDSearch files from the itron git repository

2. Set up the config file to contain the mailing list (located in /NVDSearch/docker)

3. Open /NVDSearch/docker/nvdsearch.py and configure the SMTP server address near the top of the file (defaults to the Spokane SMTP server)

4. Open a command prompt and navigate to the /NVDSearch/docker folder

5. Run "python nvdsearch.py --auto" for automatic mailing or "python nvdsearch --manual" to manually enter search terms (only supports one email address in manual mode)

6. If the script fails due to not having the correct dependenencies, use pip (or other package downloader) to obtain "requests" and "colorama"

------------------------------------

Running the python script on linux

------------------------------------

1. Download the NVDSearch files from the itron git repository

2. Set up the config file to contain the mailing list (located in /NVDSearch/docker)

3. Open /NVDSearch/docker/nvdsearch.py and configure the SMTP server address near the top of the file (defaults to the Spokane SMTP server)

4. Open a terminal and navigate to the /NVDSearch/docker folder

5. Run "python nvdsearch.py --auto" for automatic mailing or "python nvdsearch --manual" to manually enter search terms (only supports one email address in manual mode)

6. If the script fails due to not having the correct dependenencies, use apt (or other package downloader) to obtain "requests" and "colorama"

------------------------------------

Running the python script with Docker

------------------------------------

1. Download the NVDSearch files from the itron git repository

2. Set up the config file to contain the mailing list (located in /NVDSearch/docker)

3. Open /NVDSearch/docker/nvdsearch.py and configure the SMTP server address near the top of the file (defaults to the Spokane SMTP server)

4. Open a command prompt and navigate to the /NVDSearch/docker folder

5. Run "python nvdsearch.py --auto" for automatic mailing or "python nvdsearch --manual" to manually enter search terms (only supports one email address in manual mode)

6. If the script fails due to not having the correct dependenencies, use pip or apt (or other package downloader) to obtain "requests" and "colorama"

7. Once you have confirmed that the script works, run the build.sh script to generate a Docker image

8. Run the Docker image with "docker run --rm nvdsearch" (the --rm tag will delete the container after running. This does not destroy the image, just the container that is generated on runtime)
