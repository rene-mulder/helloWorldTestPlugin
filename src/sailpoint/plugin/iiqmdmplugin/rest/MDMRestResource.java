package sailpoint.plugin.iiqmdmplugin.rest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.PathSegment;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import sailpoint.api.SailPointContext;
import sailpoint.object.Attributes;
import sailpoint.object.Capability;
import sailpoint.object.Custom;
import sailpoint.object.Identity;
import sailpoint.plugin.iiqmdmplugin.MasterDataManagementPluginException;
import sailpoint.plugin.rest.AbstractPluginRestResource;
import sailpoint.plugin.rest.jaxrs.AllowAll;
import sailpoint.plugin.rest.jaxrs.SPRightsRequired;
import sailpoint.tools.GeneralException;

@SPRightsRequired(value = { "MasterDataManagementPluginRestServiceAllow" })
@Path("iiqmdmplugin")
public class MDMRestResource extends AbstractPluginRestResource {

	public final static String CONFIG_CUSTOM_OBJECT = "Master Data Manamenent Plugin Configuration";
	public final static String CONFIG_KEY_OBJECT_PERMISSIONS = "objectRights";
	public final static String CONFIG_PERMISSION_MANAGE = "MANAGE";
	public final static String CONFIG_PERMISSION_READ = "READ";
	public final static String CONFIG_PERMISSION_CREATE = "CREATE";
	public final static String CONFIG_PERMISSION_UPDATE = "UPDATE";
	public final static String CONFIG_PERMISSION_DELETE = "DELETE";
	public final static String[] CONFIG_PERMISSIONS = { CONFIG_PERMISSION_MANAGE, CONFIG_PERMISSION_CREATE, CONFIG_PERMISSION_DELETE, CONFIG_PERMISSION_READ, CONFIG_PERMISSION_UPDATE };
	
	public final static int MAX_ITEM_DEPTH = 10;

	private static Log log = LogFactory.getLog(MDMRestResource.class);

	public MDMRestResource() {
		// TODO Auto-generated constructor stub
	}
	
	/**
	 * Find and return the plugin configuraton settings Custom object.
	 * 
	 * @return Custom object containing the plugin configuration.
	 * @throws GeneralException
	 */
	private Custom getPluginConfiguration() throws GeneralException {
		log.debug("Enter: getPluginConfiguration()");
		SailPointContext context = getContext();
		Custom config = context.getObjectByName(Custom.class, CONFIG_CUSTOM_OBJECT);
		if (config == null) {
			throw new MasterDataManagementPluginException("Configuration Custom Object not found for this plugin");
		}
		return config;
	}

	/**
	 * Verify the identity's access. The configuration object for the plugin is
	 * looked up. If found, permissions will be checked per Custom object to be
	 * managed. A system administrator will have full access.
	 * 
	 * @param identity
	 * @param objectName
	 * @param permission
	 * @return
	 * @throws GeneralException
	 */
	@SuppressWarnings("unused")
	private boolean verifyAccess(Identity identity, String objectName, String permission) throws GeneralException {
		log.debug(String.format("Enter: verifyAccess(%s, %s, %s)", identity.toString(), objectName, permission));
		if (identity != null && objectName != null && permission != null) {
			if (Arrays.asList(CONFIG_PERMISSIONS).contains(permission)) {
				Custom config = getPluginConfiguration();
				if (config != null) {
					Identity.CapabilityManager cm = identity.getCapabilityManager();
					Collection<String> identityRights = cm.getEffectiveFlattenedRights();

					// Check SystemAdministrator
					if (cm.hasCapability(Capability.SYSTEM_ADMINISTRATOR)) {
						log.info("System administrator rights found. Granting permission");
						return true;
					}

					// Try other permissions
					Attributes<String, Object> attributes = config.getAttributes();
					if (attributes != null) {
						Map<String, Object> authorizations = (Map<String, Object>) attributes.get(CONFIG_KEY_OBJECT_PERMISSIONS);
						if (authorizations != null) {
							Map<String, Object> objectRights = (Map<String, Object>) authorizations.get(objectName);
							if (objectRights != null) {
								String manageAccess = (String) objectRights.get(CONFIG_PERMISSION_MANAGE);
								String specificAccess = (String) objectRights.get(permission);
								if ((manageAccess != null && identityRights.contains(manageAccess)) || (specificAccess != null && identityRights.contains(specificAccess))) {
									log.info("Required rights found. Granting permission.");
									return true;
								} else {
									log.error("Required rights not found. Not granting permission.");
								}
							} else {
								log.error(String.format("No authorizations found for custom object %s", objectName));
							}
						} else {
							log.error("No authorizations found");
						}
					} else {
						log.error(String.format("Custom object %s does not have attributes", CONFIG_CUSTOM_OBJECT));
					}
				} else {
					log.error(String.format("Configuration Custom object %s not found.", CONFIG_CUSTOM_OBJECT));
				}
			}
		}
		// If all conditions fail, no access is given.
		return false;
	}

	/**
	 * Verify the identity's access. Will look up the identity and using that,
	 * call sibling method.
	 * 
	 * @param identityName
	 * @param objectName
	 * @param permission
	 * @return
	 * @throws GeneralException
	 */
	private boolean verifyAccess(String identityName, String objectName, String permission) throws GeneralException {
		log.debug(String.format("Enter: verifyAccess(%s, %s, %s)", identityName, objectName, permission));
		return verifyAccess(getContext().getObjectByName(Identity.class, identityName), objectName, permission);
	}

	/**
	 * Verify the identity's access. Will look up the current identity name from
	 * the context and using that, call sibling method.
	 * 
	 * @param objectName
	 * @param permission
	 * @return
	 * @throws GeneralException
	 */
	private boolean verifyAccess(String objectName, String permission) throws GeneralException {
		log.debug(String.format("Enter: verifyAccess(%s, %s)", objectName, permission));
		return verifyAccess(getContext().getUserName(), objectName, permission);
	}
	
	/**
	 * Convert a list of PathSegment objects into a list of strings.
	 * 
	 * @param entryList
	 * @return
	 */
	private List<String> convertEntryList(List<PathSegment> entryList) {
		List<String> entryNamesList = new ArrayList<String>();
		if (entryList != null && !entryList.isEmpty()) {
			for (PathSegment segment: entryList) {
				String name = segment.getPath();
				log.error("Segment: " + name);
				entryNamesList.add(name);
			}
		}
		return entryNamesList;
	}
	
	private boolean isEntryExists(Map<String, Object> map, List<String> entryNameList) {
		log.debug(String.format("Enter: isEntryExists(%s, %s)", map.toString(), entryNameList.toString()));
		if (map != null && entryNameList != null && !entryNameList.isEmpty()) {
			if (entryNameList.size() > MAX_ITEM_DEPTH) {
				String message = "Entry list too deep";
				log.error(message);
				throw new WebApplicationException(new Exception(message), 500);
			}
			String key = entryNameList.get(0);
			@SuppressWarnings("unchecked")
			List<String> newEntryNameList = ((List<String>) ((ArrayList<String>) entryNameList).clone());
			newEntryNameList.remove(0);
			if (map.containsKey(key)) {
				Object entry = map.get(key);
				if (newEntryNameList.isEmpty()) {
					log.debug("Found object");
					return true;
				}
				if (entry instanceof Map) {
					log.debug("Next level");
					return isEntryExists((Map<String, Object>) entry, newEntryNameList);
				}
				if (newEntryNameList.size() == 1) {
					log.debug("Entry is leaf");
					return true;
				}
			} else {
				log.error("Entry not found");
			}
		}
		return false;
	}
	
	/**
	 * Walk down the list of entry names. If found return the entry and possibly sub-entries from that point.
	 * A leaf entry may be of any type. A non-leaf entry must be a Map.
	 * 
	 * @param map
	 * @param entryNameList
	 * @return
	 * @throws WebApplicationException
	 */
	private Object internalGetEntry(Map<String, Object> map, List<String> entryNameList) throws WebApplicationException {
		log.debug(String.format("Enter: internalGetEntry(%s, %s)", map.toString(), entryNameList.toString()));
		if (map != null && entryNameList != null && !entryNameList.isEmpty()) {
			if (entryNameList.size() > MAX_ITEM_DEPTH) {
				String message = "Entry list too deep";
				log.error(message);
				throw new WebApplicationException(new Exception(message), 500);
			}
			String key = entryNameList.get(0);
			@SuppressWarnings("unchecked")
			List<String> newEntryNameList = ((List<String>) ((ArrayList<String>) entryNameList).clone());
			newEntryNameList.remove(0);
			if (map.containsKey(key)) {
				Object entry = map.get(key);
				if (newEntryNameList.isEmpty()) {
					log.debug("Returning object");
					return entry;
				}
				if (entry instanceof Map) {
					log.debug("Next level");
					return internalGetEntry((Map<String, Object>) entry, newEntryNameList);
				} else {
					String message = "Entry is not a leaf, so must be a Map, but isn't"; 
					log.error(message);
					throw new WebApplicationException(new Exception(message), 500);
				}
			} else {
				log.error("Entry not found");
			}
		}
		return null;
	}

	/**
	 * Walk down the list of entry names. If found return the entry and possibly sub-entries from that point.
	 * A leaf entry may be of any type. A non-leaf entry must be a Map.
	 * 
	 * @param map
	 * @param entryNameList
	 * @return
	 * @throws WebApplicationException
	 */
	private Map<String, Object> internalSetEntry(Map<String, Object> map, List<String> entryNameList, Object value) throws WebApplicationException {		
		log.debug(String.format("Enter: internalSetEntry(%s, %s, %s)", map.toString(), entryNameList.toString(), value));
		
		if (map != null && entryNameList != null && !entryNameList.isEmpty()) {
			if (entryNameList.size() > MAX_ITEM_DEPTH) {
				String message = "Entry list too deep";
				log.error(message);
				throw new WebApplicationException(new Exception(message), 500);
			}
			String key = entryNameList.get(0);
			@SuppressWarnings("unchecked")
			List<String> newEntryNameList = ((List<String>) ((ArrayList<String>) entryNameList).clone());
			newEntryNameList.remove(0);
			if (map.containsKey(key)) {
				Object entry = map.get(key);
				if (newEntryNameList.isEmpty()) {
					log.debug("Found leaf, setting value");
					map.put(key, value);
					return map;
				}
				if (!(entry instanceof Map)) {
					log.debug("Entry is not a leaf. Converting to Map");
					entry = new HashMap<String, Object>();
				}
				log.debug("Next level");
				map.put(key, internalSetEntry((Map<String, Object>) entry, newEntryNameList, value));
				return map;
			} else {
				log.warn("Entry not found, creating new entry");
				Map entry = new HashMap<String, Object>();
				if (newEntryNameList.isEmpty()) {
					log.debug("Found leaf, setting value");
					map.put(key, value);
				} else {
					log.debug("Next level");
					map.put(key, internalSetEntry((Map<String, Object>) entry, newEntryNameList, value));
				}
				return map;
			}
		}
		return null;
	}
	
	/**
	 * Look up the specified entry and remove it from the map.
	 * 
	 * @param map
	 * @param entryNameList
	 * @return
	 * @throws WebApplicationException
	 */
	private Map<String, Object> internalDeleteEntry(Map<String, Object> map, List<String> entryNameList) throws WebApplicationException {
		log.debug(String.format("Enter: internalDeleteEntry(%s, %s)", map.toString(), entryNameList.toString()));
		
		if (map != null && entryNameList != null && !entryNameList.isEmpty()) {
			if (entryNameList.size() > MAX_ITEM_DEPTH) {
				String message = "Entry list too deep";
				log.error(message);
				throw new WebApplicationException(new Exception(message), 500);
			}
			String key = entryNameList.get(0);
			@SuppressWarnings("unchecked")
			List<String> newEntryNameList = ((List<String>) ((ArrayList<String>) entryNameList).clone());
			newEntryNameList.remove(0);
			if (map.containsKey(key)) {
				Object entry = map.get(key);
				if (newEntryNameList.isEmpty()) {
					log.debug("Found leaf, deleting entry");
					map.remove(key);
					return map;
				}
				if (!(entry instanceof Map)) {
					String message = "Next subentry not found";
					log.error(message);
					throw new WebApplicationException(new Exception(message), 404);
				}
				log.debug("Next level");
				map.put(key, internalDeleteEntry((Map<String, Object>) entry, newEntryNameList));
				return map;
			} else {
				String message = "Entry not found, creating new entry";
				log.error(message);
				throw new WebApplicationException(new Exception(message), 404);
			}
		}
		return null;
	}

	/**
	 * 
	 * @param map
	 * @param entryList
	 * @return
	 * @throws WebApplicationException
	 */
	private boolean isEntryExistsWithPathSegments(Map<String, Object> map, List<PathSegment> entryList, boolean lastIsValue) throws WebApplicationException {
		log.debug(String.format("Enter: isEntryExistsWithPathSegments(%s, %s)", map.toString(), entryList.toString()));
		List<String> names = convertEntryList(entryList);
		if (names != null && !names.isEmpty()) {
			if (lastIsValue) {
				// remove last item as that is considered the value
				int size = names.size();
				names.remove(size - 1);
			}
			if (!names.isEmpty()) {
				return isEntryExists(map, names);
			}
		}
		return false;
	}
	
	/**
	 * 
	 * @param map
	 * @param entryList
	 * @return 
	 */
	private Map<String, Object> deleteEntryWithPathSegments(Map<String, Object> map, List<PathSegment> entryList) {
		log.debug(String.format("Enter: deleteEntryWithPathSegments(%s, %s)", map.toString(), entryList.toString()));
		List<String> names = convertEntryList(entryList);
		if (names != null && !names.isEmpty()) {
			if (names.size() < 1) {
				throw new WebApplicationException(new Exception("Not enough entries, need at least a key and value"), 500);
			}
			map = internalDeleteEntry(map, names);
		}
		return map;
	}
	
	/**
	 * 
	 * @param map
	 * @param entryList
	 * @param value
	 * @return
	 * @throws WebApplicationException
	 */
	private Map setEntryWithPathSegments(Map<String, Object> map, List<PathSegment> entryList, Object value) throws WebApplicationException {
		log.debug(String.format("Enter: setEntryWithPathSegments(%s, %s, %s)", map.toString(), entryList.toString(), value));
		List<String> names = convertEntryList(entryList);
		if (names != null && !names.isEmpty()) {
			if (names.size() < 1 || value == null) {
				throw new WebApplicationException(new Exception("Not enough entries, need at least a key and value"), 500);
			}
			map =  internalSetEntry(map, names, value);
		}
		return map;
	}

	/**
	 * 
	 * @param map
	 * @param entryList
	 * @return
	 * @throws WebApplicationException
	 */
	private Map setEntryWithPathSegments(Map<String, Object> map, List<PathSegment> entryList) throws WebApplicationException {
		log.debug(String.format("Enter: setEntryWithPathSegments(%s, %s)", map.toString(), entryList.toString()));
		List<String> names = convertEntryList(entryList);
		if (names != null && !names.isEmpty()) {
			if (names.size() < 2) {
				throw new WebApplicationException(new Exception("Not enough entries, need at least a key and value"), 500);
			}
			int size = names.size();
			String value = names.get(size - 1);
			names.remove(size - 1);
			map = internalSetEntry(map, names, value);
		}
		return map;
	}
		
	
	/**
	 * 
	 * @param map
	 * @param entryList
	 * @return
	 * @throws WebApplicationException
	 */
	private Object getEntryWithPathSegments(Map<String, Object> map, List<PathSegment> entryList) throws WebApplicationException {
		log.debug(String.format("Enter: getEntryWithPathSegments(%s, %s)", map.toString(), entryList.toString()));
		List<String> names = convertEntryList(entryList);
		if (names != null && !names.isEmpty()) {
			return internalGetEntry(map, names);
		}
		return null;
	}
	
	@AllowAll
	@POST
	@Path("setEntry/{objectName}/{entry:.*}")
    @Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.TEXT_PLAIN)
	public String setEntry(@PathParam("objectName") String objectName, @PathParam("entry") List<PathSegment> entries, Object data) throws GeneralException {
		log.debug(String.format("Enter: setEntry(%s, %s, %s)", objectName, entries.toString(), data));
		
		if (!(data instanceof String || data instanceof Map || data instanceof List)) {
			String message = String.format("Unsupported data type: %s", data.getClass().getName());
			log.error(message);
			throw new WebApplicationException(new Exception(message), 500);
		}
		
		try {
			SailPointContext context = getContext();
			Custom custom = context.getObjectByName(Custom.class, objectName);
			if (custom != null) {
				Attributes<String, Object> attributes = custom.getAttributes();
				if (attributes == null) {
					attributes = new Attributes();
				}

				Map<String, Object> map = attributes.getMap();
				if (map == null) {
					map = new HashMap<String, Object>();
				}
				boolean exists = isEntryExistsWithPathSegments(map, entries, false);
				
				if ((exists && verifyAccess(objectName, CONFIG_PERMISSION_UPDATE) || (verifyAccess(objectName, CONFIG_PERMISSION_CREATE)))) {
					log.debug("Access granted");
					map = setEntryWithPathSegments(map, entries, data);
					attributes.setMap(map);
					custom.setAttributes(attributes);
					context.startTransaction();
					context.saveObject(custom);
					context.commitTransaction();
				} else {
					throw new WebApplicationException(new Exception("Unauthorized"), 401);
				}
			} else {
				String message = "Custom object not found";
				log.error(message);
				throw new WebApplicationException(new Exception(message), 404);
			}
		} catch (MasterDataManagementPluginException e) {
			log.error(e);
			throw new WebApplicationException(e, 500);
		}		
		return "";		
	}
	
	/**
	 * Set a new value for an entry. The last item on the list is considered a
	 * leaf. The list must thus contain at least of two items: key and value
	 * 
	 * @param objectName
	 * @param entries
	 * @return
	 * @throws GeneralException
	 */
	@AllowAll
	@GET
	@Path("setEntry/{objectName}/{entry:.*}")
	@Produces(MediaType.TEXT_PLAIN)
	public Object setEntry(@PathParam("objectName") String objectName, @PathParam("entry") List<PathSegment> entries) throws GeneralException {
		log.debug(String.format("Enter: setEntry(%s, %s)", objectName, entries.toString()));
		try {
			SailPointContext context = getContext();
			Custom custom = context.getObjectByName(Custom.class, objectName);
			if (custom != null) {
				Attributes<String, Object> attributes = custom.getAttributes();
				if (attributes == null) {
					attributes = new Attributes();
				}

				Map<String, Object> map = attributes.getMap();
				if (map == null) {
					map = new HashMap<String, Object>();
				}
				boolean exists = isEntryExistsWithPathSegments(map, entries, true);

				if ((exists && verifyAccess(objectName, CONFIG_PERMISSION_UPDATE) || (verifyAccess(objectName, CONFIG_PERMISSION_CREATE)))) {
					log.debug("Access granted");
					map = setEntryWithPathSegments(map, entries);
					attributes.setMap(map);
					custom.setAttributes(attributes);
					context.startTransaction();
					context.saveObject(custom);
					context.commitTransaction();
				} else {
					throw new WebApplicationException(new Exception("Unauthorized"), 401);
				}
			} else {
				String message = "Custom object not found";
				log.error(message);
				throw new WebApplicationException(new Exception(message), 404);
			}
		} catch (MasterDataManagementPluginException e) {
			log.error(e);
			throw new WebApplicationException(e, 500);
		}
		return "";
	}
	

	/**
	 * Get a (sub*)entry from a Custom object.
	 * 
	 * @param objectName
	 * @return
	 * @throws GeneralException
	 */
	@AllowAll
	@GET
	@Path("getEntry/{objectName}/{entry:.*}")
	@Produces(MediaType.APPLICATION_JSON)
	public Object getEntry(@PathParam("objectName") String objectName, @PathParam("entry") List<PathSegment> entries) throws GeneralException {
		log.debug(String.format("Enter: getEntry(%s, %s)", objectName, entries.toString()));		
		try {
			if (verifyAccess(objectName, CONFIG_PERMISSION_READ)) {
				log.debug("Access granted");
				Custom custom = getContext().getObjectByName(Custom.class, objectName);
				if (custom != null) {
					Attributes<String, Object> attributes = custom.getAttributes();
					if (attributes != null) {
						Map<String, Object> map = attributes.getMap();
						return getEntryWithPathSegments(map, entries);
					}
				}
			} else {
				throw new WebApplicationException(new Exception("Unauthorized"), 401);				
			}
		} catch (MasterDataManagementPluginException e) {
			log.error(e);
			throw new WebApplicationException(e, 500);
		}
		return new HashMap<String, Object>();
	}

	/**
	 * Get the full context of a Custom object.
	 * 
	 * @param objectName
	 * @return
	 * @throws GeneralException
	 */
	@AllowAll
	@GET
	@Path("getCustom/{objectName}")
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getCustom(@PathParam("objectName") String objectName) throws GeneralException {
		log.debug(String.format("Enter: getCustom(%s)", objectName));		
		try {
			if (verifyAccess(objectName, CONFIG_PERMISSION_READ)) {
				log.debug("Access granted");
				Custom custom = getContext().getObjectByName(Custom.class, objectName);
				if (custom != null) {
					Attributes<String, Object> attributes = custom.getAttributes();
					if (attributes != null) {
						Map<String, Object> map = attributes.getMap();
						return map;
					}
				}
			} else {
				throw new WebApplicationException(new Exception("Unauthorized"), 401);				
			}
		} catch (MasterDataManagementPluginException e) {
			log.error(e);
			throw new WebApplicationException(e, 500);
		}
		return new HashMap<String, Object>();
	}
	
	/**
	 * 
	 * @param objectName
	 * @param entries
	 * @return
	 * @throws GeneralException
	 */
	@AllowAll
	@DELETE
	@Path("deleteEntry/{objectName}/{entry:.*}")
	@Produces(MediaType.TEXT_PLAIN)
	public String deleteEntry(@PathParam("objectName") String objectName, @PathParam("entry") List<PathSegment> entries) throws GeneralException {
		log.debug(String.format("Enter: getEntry(%s, %s)", objectName, entries.toString()));		
		try {
			if (verifyAccess(objectName, CONFIG_PERMISSION_DELETE)) {
				Custom custom = getContext().getObjectByName(Custom.class, objectName);
				if (custom != null) {
					Attributes<String, Object> attributes = custom.getAttributes();
					if (attributes != null) {
						SailPointContext context = getContext();
						Map<String, Object> map = attributes.getMap();
						map = deleteEntryWithPathSegments(map, entries);
						attributes.setMap(map);
						custom.setAttributes(attributes);
						context.startTransaction();
						context.saveObject(custom);
						context.commitTransaction();
					}
				}
			} else {
				throw new WebApplicationException(new Exception("Unauthorized"), 401);				
			}
		} catch (MasterDataManagementPluginException e) {
			log.error(e);
			throw new WebApplicationException(e, 500);
		}
		return "";
	}
	
	/**
	 * Test whether the plugin responds.
	 * 
	 * @return
	 */
	@AllowAll
	@GET
	@Path("ping")
	@Produces(MediaType.TEXT_PLAIN)
	public String ping() {
		return "pong";
	}
	
}
