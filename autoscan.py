from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
import xml.etree.ElementTree as ET
from lxml import etree
import time

connection = UnixSocketConnection()
transform = EtreeTransform()

with Gmp(connection, transform=transform) as gmp:
    # Retrieve GMP version supported by the remote daemon
    version = gmp.get_version()

    # Prints the XML in beautiful form
    pretty_print(version)

    # Login
    gmp.authenticate('admin', 'admin')

    #Is target created
    xml = etree.tostring(gmp.get_targets())

    root = ET.fromstring(xml)
    target = root.findall('.//target')
    target_found = any(target.find('name').text == "ALL internals tools" for target in target if target.find('name') is not None)
    print("Target 'ALL internals tools' found:", target_found)

    if target_found == False:
        print("Veuillez crée une target list avec les ip des pod et appelez la 'ALL internals tools' ")

    #Get target id
    for target in root.findall('.//target'):
        if target.find('name').text == 'ALL internals tools':
            target_id = target.get('id')
            print("The ID of 'ALL internals tools' is:", target_id)


    #Get port list id
    xml = etree.tostring(gmp.get_port_lists())

    root = ET.fromstring(xml)
    for port_list in root.findall('port_list'):
        if port_list.find('name').text == "All TCP and Nmap top 100 UDP":
            port_list_id = port_list.get('id')
            print("The ID of 'All TCP and Nmap top 100 UDP' is:", port_list_id)

    #Get config id
    xml = etree.tostring(gmp.get_scan_configs())
    root = ET.fromstring(xml)

    for config in root.findall('.//config'):
        if config.find('name').text == 'Full and fast':
            config_id = config.get('id')
            print("The ID of 'Full and fast' is:", config_id)

    #Get scanner id
    xml = etree.tostring(gmp.get_scanners())
    root = ET.fromstring(xml)

    for scanner in root.findall('.//scanner'):
        if scanner.find('name').text == 'OpenVAS Default':
            scanner_id = scanner.get('id')
            print("The ID of 'OpenVAS Default' is:", scanner_id)

    #Does task exist
    tasks = gmp.get_tasks()

    task_names = tasks.xpath('task/name/text()')
    for name in task_names:
        if name == "all internal tools":
            have_task = True
            break
        else:
            have_task = False

    if have_task == False:
        response = gmp.create_task(name='all internal tools', config_id=config_id, target_id=target_id, scanner_id=scanner_id)

    #Get task id
    root = ET.fromstring(etree.tostring(tasks))

    for task in root.findall('.//task'):
        if task.find('name').text == 'all internal tools':
            task_id = task.get('id')
            print("The ID of 'all internal tools' task is:", task_id)

    #Start the task
    gmp.start_task(task_id=task_id)

    while True:
        xml = etree.tostring(gmp.get_tasks())
        root = ET.fromstring(xml)

        for task in root.findall('.//task'):
            current_id = task.get('id')
            if current_id == task_id:
                status_element = task.find('.//status')
                if status_element is not None:
                    task_status = status_element.text
                    print(f"Status de la tache {task_id}: {task_status}")

                    if task_status == 'Done':
                        print("Scan terminé")
                        break
            time.sleep(15)