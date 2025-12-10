# mtga_collection_export.py
Tool for exporting your Magic The Gathering: Arena card collection to a text file on Windows PCs.

Implementation Notes:
* MTG: Arena (for Windows) must be running; the tool reads the cards from memory
* Card IDs are queried against Scryfall to determine the card name
* Basic Lands are excluded
* Uknown cards (not on Scryfall) are excluded
