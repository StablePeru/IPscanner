import logging

def setup_logger():
    logger = logging.getLogger('ip_scanner')
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler('ip_scanner.log')
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger
